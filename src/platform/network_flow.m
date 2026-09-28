// Experimental connected UDP backend. All mutable state is serialized on queue.
// Rust owns separate RX/TX notification readers; this object owns duplicated
// nonblocking writers until the last asynchronous callback releases the object.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

#define RX_SLOTS 256
#define TX_SLOTS 1024
#define PACKET_CAPACITY 2048

@interface INFlow : NSObject {
@public
    uint8_t packets[RX_SLOTS][PACKET_CAPACITY];
    size_t lengths[RX_SLOTS];
    size_t head, count, pending;
    int error, rxWriter, txWriter;
    bool closing, ready, receiving;
}
@property nw_connection_t connection;
@property dispatch_queue_t queue;
- (void)receive;
@end

static void notify(int fd) {
    uint8_t byte = 1;
    // A full notification socket already represents pending work.
    ssize_t result;
    do {
        result = send(fd, &byte, 1, MSG_DONTWAIT | MSG_NOSIGNAL);
    } while (result < 0 && errno == EINTR);
    if (result < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        int error = errno;
        // A failed notification must not leave the worker asleep with queued
        // packets. EOF wakes kqueue and makes Rust fail this flow visibly.
        (void)shutdown(fd, SHUT_WR);
        fprintf(stderr, "Network.framework notification failed: errno=%d\n", error);
    }
}
static int posix_error(nw_error_t error) {
    return nw_error_get_error_domain(error) == nw_error_domain_posix
        ? nw_error_get_error_code(error) : EIO;
}

@implementation INFlow
- (void)dealloc {
    if (rxWriter >= 0) close(rxWriter);
    if (txWriter >= 0) close(txWriter);
}
- (void)receive {
    if (closing || error || !ready || receiving || count == RX_SLOTS) return;
    receiving = true;
    nw_connection_receive_message(self.connection, ^(dispatch_data_t data, nw_content_context_t context, bool complete, nw_error_t e) {
        (void)context;
        self->receiving = false;
        if (self->closing) return;
        if (e) {
            self->error = posix_error(e);
            notify(self->rxWriter);
            notify(self->txWriter);
            return;
        }
        size_t length = data ? dispatch_data_get_size(data) : 0;
        if (complete && length > 0 && length <= PACKET_CAPACITY) {
            size_t slot = (self->head + self->count) % RX_SLOTS;
            dispatch_data_apply(data, ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                (void)region;
                memcpy(self->packets[slot] + offset, buffer, size);
                return true;
            });
            self->lengths[slot] = length;
            self->count++;
            if (self->count == 1) notify(self->rxWriter);
        }
        // Invalid/oversized/empty datagrams are discarded. Stop posting reads
        // when our bounded ring is full; the Rust consumer resumes them.
        [self receive];
    });
}
@end

void *in_flow_open(const char *host, const char *port, const char *localHost,
                   const char *localPort, int rxWriter, int txWriter) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow->rxWriter = -1;
        flow->txWriter = -1;
        flow->rxWriter = dup(rxWriter);
        flow->txWriter = dup(txWriter);
        if (flow->rxWriter < 0 || flow->txWriter < 0) return NULL;
        flow.queue = dispatch_queue_create("interestun.udp.network", DISPATCH_QUEUE_SERIAL);
        nw_parameters_t parameters = nw_parameters_create_secure_udp(
            NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        nw_parameters_set_reuse_local_address(parameters, true);
        nw_parameters_set_local_endpoint(parameters, nw_endpoint_create_host(localHost, localPort));
        flow.connection = nw_connection_create(nw_endpoint_create_host(host, port), parameters);
        nw_connection_set_queue(flow.connection, flow.queue);
        __weak INFlow *weakFlow = flow;
        nw_connection_set_state_changed_handler(flow.connection, ^(nw_connection_state_t state, nw_error_t e) {
            INFlow *f = weakFlow;
            if (!f || f->closing) return;
            if (state == nw_connection_state_ready) {
                f->ready = true;
                char *description = nw_connection_copy_description(f.connection);
                if (description) { fprintf(stderr, "Network.framework peer: %s\n", description); free(description); }
                [f receive];
            } else if (state == nw_connection_state_failed || state == nw_connection_state_waiting) {
                // Fail visibly instead of silently comparing a stuck flow.
                f->error = e ? posix_error(e) : ENETDOWN;
            }
            notify(f->rxWriter);
            notify(f->txWriter);
        });
        nw_connection_start(flow.connection);
        return (__bridge_retained void *)flow;
    }
}

// Return a consumed prefix, or negative POSIX errno. Each dispatch_data owns a
// synchronous copy before returning to Rust. Completions wake the TX worker.
int in_flow_send(void *handle, const uint8_t *const *buffers, const size_t *lengths, size_t count) {
    @autoreleasepool {
        INFlow *flow = (__bridge INFlow *)handle;
        __block int result = 0;
        dispatch_sync(flow.queue, ^{
            if (flow->error) { result = -flow->error; return; }
            if (!flow->ready || flow->pending == TX_SLOTS) { result = -EAGAIN; return; }
            size_t accepted = MIN(count, TX_SLOTS - flow->pending);
            flow->pending += accepted;
            nw_connection_batch(flow.connection, ^{
                for (size_t i = 0; i < accepted; i++) {
                    dispatch_data_t data = dispatch_data_create(buffers[i], lengths[i], NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                    nw_connection_send(flow.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t e) {
                        bool wasFull = flow->pending == TX_SLOTS;
                        flow->pending--;
                        if (flow->closing) return;
                        if (e) {
                            flow->error = posix_error(e);
                            notify(flow->rxWriter);
                            notify(flow->txWriter);
                        } else if (wasFull) notify(flow->txWriter);
                    });
                }
            });
            result = (int)accepted;
        });
        return result;
    }
}

int in_flow_receive(void *handle, uint8_t *const *buffers, size_t *lengths, size_t capacity) {
    @autoreleasepool {
        INFlow *flow = (__bridge INFlow *)handle;
        __block int result = 0;
        dispatch_sync(flow.queue, ^{
            size_t available = MIN(capacity, flow->count);
            for (size_t i = 0; i < available; i++) {
                size_t slot = flow->head;
                lengths[i] = flow->lengths[slot];
                memcpy(buffers[i], flow->packets[slot], lengths[i]);
                flow->head = (slot + 1) % RX_SLOTS;
                flow->count--;
            }
            [flow receive];
            result = available ? (int)available : -(flow->error ? flow->error : EAGAIN);
        });
        return result;
    }
}

void in_flow_close(void *handle) {
    @autoreleasepool {
        INFlow *flow = (__bridge_transfer INFlow *)handle;
        dispatch_sync(flow.queue, ^{
            flow->closing = true;
            nw_connection_set_state_changed_handler(flow.connection, nil);
            nw_connection_cancel(flow.connection);
        });
    }
}
