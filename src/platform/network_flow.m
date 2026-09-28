// Callback delivery remains serial; packet handoff uses a bounded SPSC ring.
// Rust never waits for the callback queue in the send/receive hot paths.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <errno.h>
#include <dlfcn.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <unistd.h>

#define RX_SLOTS 1024
#ifdef IN_NETWORK_MULTIPLE
#define RX_WINDOW 256
#else
#define RX_WINDOW 128
#endif
#define RX_BATCH 128
#define TX_SLOTS 1024
#define PACKET_CAPACITY 2048

#ifdef IN_NETWORK_MULTIPLE
// Private SPI: verified against macOS 27.0 (26A428), not a public SDK contract.
// The final callback flag means last in this group, NOT message completeness.
// See docs/network-framework-audit.md and tests/network_multiple.m.
typedef void (*INReceiveMultiple)(nw_connection_t, uint32_t, uint32_t, nw_connection_receive_completion_t);
#endif

@interface INFlow : NSObject {
@public
    // One producer (the serial callback queue) and one Rust receive consumer.
    void *packets[RX_SLOTS];
    size_t lengths[RX_SLOTS];
    _Atomic(size_t) readIndex;
    char readPadding[128];
    _Atomic(size_t) writeIndex;
    char writePadding[128];
    _Atomic(size_t) reserved;
    _Atomic(bool) refillScheduled;
#ifdef IN_NETWORK_MULTIPLE
    INReceiveMultiple receiveMultiple;
#else
    bool notifyScheduled; // Only the callback queue accesses this.
#endif
    _Atomic(size_t) pending;
    _Atomic(int) error;
    _Atomic(bool) closing, ready;
    void *wakeContext;
    void (*wakeWorker)(void *, bool);
    void (*releaseContext)(void *);
}
// Set once before publishing the handle; immutable during worker access.
@property (nonatomic, strong) nw_connection_t connection;
@property (nonatomic, strong) dispatch_queue_t queue;
- (void)refill;
- (void)scheduleRefill;
#ifndef IN_NETWORK_MULTIPLE
- (void)scheduleNotify;
#endif
@end

static void notify(INFlow *flow, bool tx) {
    if (flow->wakeWorker) flow->wakeWorker(flow->wakeContext, tx);
}
static int posix_error(nw_error_t error) {
    return nw_error_get_error_domain(error) == nw_error_domain_posix
        ? nw_error_get_error_code(error) : EIO;
}

static void fail(INFlow *flow, int error) {
    atomic_store_explicit(&flow->error, error, memory_order_release);
    notify(flow, false);
    notify(flow, true);
}

@implementation INFlow
- (void)dealloc {
    if (releaseContext) releaseContext(wakeContext);
}
#ifndef IN_NETWORK_MULTIPLE
- (void)scheduleNotify {
    if (notifyScheduled) return;
    notifyScheduled = true;
    // Always schedule a notification for a published group. Testing an
    // empty-to-nonempty transition from two independently changing cursors can
    // miss a consumer's final drain. This task also handles a lone datagram.
    dispatch_async(self.queue, ^{
        self->notifyScheduled = false;
        if (atomic_load_explicit(&self->writeIndex, memory_order_acquire) !=
            atomic_load_explicit(&self->readIndex, memory_order_acquire) &&
            !atomic_load_explicit(&self->closing, memory_order_acquire)) notify(self, false);
    });
}
#endif
- (void)scheduleRefill {
    if (atomic_load_explicit(&reserved, memory_order_relaxed) > RX_WINDOW / 2 ||
        !atomic_load_explicit(&ready, memory_order_acquire) ||
        atomic_load_explicit(&closing, memory_order_acquire) ||
        atomic_exchange_explicit(&refillScheduled, true, memory_order_acq_rel)) return;
    dispatch_async(self.queue, ^{
        atomic_store_explicit(&self->refillScheduled, false, memory_order_release);
        [self refill];
    });
}
#ifdef IN_NETWORK_MULTIPLE
- (void)refill {
    if (atomic_load_explicit(&closing, memory_order_acquire) ||
        atomic_load_explicit(&error, memory_order_acquire) ||
        !atomic_load_explicit(&ready, memory_order_acquire) ||
        atomic_load_explicit(&reserved, memory_order_relaxed)) return;
    size_t start = atomic_load_explicit(&writeIndex, memory_order_relaxed);
    size_t read = atomic_load_explicit(&readIndex, memory_order_acquire);
    size_t n = MIN(RX_WINDOW, RX_SLOTS - (start - read));
    if (!n) return;
    atomic_store_explicit(&reserved, n, memory_order_relaxed);
    __block size_t write = start;
    receiveMultiple(self.connection, 1, (uint32_t)n,
        ^(dispatch_data_t data, nw_content_context_t context, bool last, nw_error_t e) {
            (void)context;
            if (atomic_load_explicit(&self->closing, memory_order_acquire)) {
                // Close can begin between inline callbacks in this group.
                // Those references were never published to the Rust consumer.
                if (last) {
                    for (size_t i = start; i != write; i++) {
                        dispatch_data_t abandoned = (__bridge_transfer dispatch_data_t)self->packets[i % RX_SLOTS];
                        (void)abandoned;
                    }
                    atomic_store_explicit(&self->reserved, 0, memory_order_relaxed);
                }
                return;
            }
            size_t length = data ? dispatch_data_get_size(data) : 0;
            if (!e && length > 0 && length <= PACKET_CAPACITY) {
                if (write - start >= n) {
                    fail(self, EOVERFLOW);
                } else {
                    size_t slot = write++ % RX_SLOTS;
                    self->packets[slot] = (__bridge_retained void *)data;
                    self->lengths[slot] = length;
                }
            }
            if (e) fail(self, posix_error(e));
            // This SPI calls the block inline for each datagram in its batch.
            // The boolean means LAST IN BATCH, not message completeness.
            if (last) {
                // A consumer acquiring this publication must also observe
                // that reservation has ended, so it can request a refill if
                // this group fills the ring before the producer posts again.
                atomic_store_explicit(&self->reserved, 0, memory_order_relaxed);
                atomic_store_explicit(&self->writeIndex, write, memory_order_release);
                if (write != start) notify(self, false);
                [self refill];
            }
        });
}
#else
- (void)refill {
    if (atomic_load_explicit(&closing, memory_order_acquire) ||
        atomic_load_explicit(&error, memory_order_acquire) ||
        !atomic_load_explicit(&ready, memory_order_acquire)) return;
    size_t write = atomic_load_explicit(&writeIndex, memory_order_relaxed);
    size_t read = atomic_load_explicit(&readIndex, memory_order_acquire);
    size_t posted = atomic_load_explicit(&reserved, memory_order_relaxed);
    size_t n = MIN(RX_WINDOW - posted, RX_SLOTS - (write - read) - posted);
    atomic_store_explicit(&reserved, posted + n, memory_order_relaxed);
    if (!n) return;
    nw_connection_batch(self.connection, ^{
        for (size_t i = 0; i < n; i++) {
            nw_connection_receive_message(self.connection, ^(dispatch_data_t data, nw_content_context_t context, bool complete, nw_error_t e) {
                (void)context;
                if (atomic_load_explicit(&self->closing, memory_order_acquire)) return;
                size_t length = data ? dispatch_data_get_size(data) : 0;
                bool valid = !e && complete && length > 0 && length <= PACKET_CAPACITY;
                atomic_fetch_sub_explicit(&self->reserved, 1, memory_order_relaxed);
                if (valid) {
                    size_t write = atomic_load_explicit(&self->writeIndex, memory_order_relaxed);
                    size_t slot = write % RX_SLOTS;
                    self->packets[slot] = (__bridge_retained void *)data;
                    self->lengths[slot] = length;
                    atomic_store_explicit(&self->writeIndex, write + 1, memory_order_release);
                    [self scheduleNotify];
                }
                if (e) { fail(self, posix_error(e)); return; }
                [self scheduleRefill];

            });
        }
    });
}
#endif

@end

void *in_flow_open(const char *host, const char *port, const char *localHost,
                   const char *localPort, void *context, void (*wake)(void *, bool), void (*release)(void *)) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        atomic_init(&flow->readIndex, 0);
        atomic_init(&flow->writeIndex, 0);
        atomic_init(&flow->reserved, 0);
        atomic_init(&flow->pending, 0);
        atomic_init(&flow->error, 0);
        atomic_init(&flow->closing, false);
        atomic_init(&flow->ready, false);
        atomic_init(&flow->refillScheduled, false);
        flow->wakeContext = context;
        flow->wakeWorker = wake;
        flow->releaseContext = release;
        #ifdef IN_NETWORK_MULTIPLE
        flow->receiveMultiple = (INReceiveMultiple)dlsym(RTLD_DEFAULT, "nw_connection_receive_multiple");
        if (!flow->receiveMultiple) {
            fprintf(stderr, "Network.framework: private receive_multiple SPI unavailable; rebuild without apple-network-multiple\n");
            errno = ENOTSUP;
            return NULL;
        }
        fprintf(stderr, "Network.framework receive: experimental private receive_multiple (max %d)\n", RX_WINDOW);
        #else
        fprintf(stderr, "Network.framework receive: public receive_message (window %d)\n", RX_WINDOW);
        #endif
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
            if (!f || atomic_load_explicit(&f->closing, memory_order_acquire)) return;
            if (state == nw_connection_state_ready) {
                atomic_store_explicit(&f->ready, true, memory_order_release);
                char *description = nw_connection_copy_description(f.connection);
                if (description) { fprintf(stderr, "Network.framework peer: %s\n", description); free(description); }
                [f refill];
            } else if (state == nw_connection_state_failed || state == nw_connection_state_waiting) {
                fail(f, e ? posix_error(e) : ENETDOWN);
            }
            notify(f, false);
            notify(f, true);
        });
        nw_connection_start(flow.connection);
        return (__bridge_retained void *)flow;
    }
}

// nw_connection_batch invokes its block synchronously. Only owned dispatch_data
// copies and retained flow references escape to completion callbacks.
int in_flow_send(void *handle, const uint8_t *const *buffers, const size_t *lengths, size_t count) {
    @autoreleasepool {
        INFlow *flow = (__bridge INFlow *)handle;
        int error = atomic_load_explicit(&flow->error, memory_order_acquire);
        if (error) return -error;
        if (!atomic_load_explicit(&flow->ready, memory_order_acquire)) return -EAGAIN;
        size_t pending = atomic_load_explicit(&flow->pending, memory_order_relaxed);
        size_t accepted;
        do {
            if (pending == TX_SLOTS) return -EAGAIN;
            accepted = MIN(count, TX_SLOTS - pending);
        } while (!atomic_compare_exchange_weak_explicit(&flow->pending, &pending, pending + accepted,
                                                        memory_order_acq_rel, memory_order_relaxed));
        nw_connection_batch(flow.connection, ^{
            for (size_t i = 0; i < accepted; i++) {
                dispatch_data_t data = dispatch_data_create(buffers[i], lengths[i], NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                nw_connection_send(flow.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t e) {
                    size_t previous = atomic_fetch_sub_explicit(&flow->pending, 1, memory_order_acq_rel);
                    if (atomic_load_explicit(&flow->closing, memory_order_acquire)) return;
                    if (e) fail(flow, posix_error(e));
                    else if (previous == TX_SLOTS) notify(flow, true);
                });
            }
        });
        return (int)accepted;
    }
}

int in_flow_receive(void *handle, uint8_t *const *buffers, size_t *lengths, size_t capacity) {
    @autoreleasepool {
        INFlow *flow = (__bridge INFlow *)handle;
        dispatch_data_t batch[RX_BATCH];
        size_t read = atomic_load_explicit(&flow->readIndex, memory_order_relaxed);
        size_t write = atomic_load_explicit(&flow->writeIndex, memory_order_acquire);
        size_t available = MIN(MIN(capacity, RX_BATCH), write - read);
        for (size_t i = 0; i < available; i++) {
            size_t slot = (read + i) % RX_SLOTS;
            batch[i] = (__bridge_transfer dispatch_data_t)flow->packets[slot];
            lengths[i] = flow->lengths[slot];
        }
        // Release slots only after their references have moved into this batch.
        atomic_store_explicit(&flow->readIndex, read + available, memory_order_release);
        if (available) [flow scheduleRefill];
        // No staging-payload copy and no dispatch_sync: transfer retained data
        // references through the SPSC ring, then copy into Rust's cached slots.
        for (size_t i = 0; i < available; i++) {
            dispatch_data_apply(batch[i], ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                (void)region;
                memcpy(buffers[i] + offset, buffer, size);
                return true;
            });
        }
        int error = atomic_load_explicit(&flow->error, memory_order_acquire);
        return available ? (int)available : -(error ? error : EAGAIN);
    }
}

void in_flow_close(void *handle) {
    @autoreleasepool {
        INFlow *flow = (__bridge_transfer INFlow *)handle;
        atomic_store_explicit(&flow->closing, true, memory_order_release);
        // Lifecycle-only barrier; no worker hot path synchronizes to this queue.
        dispatch_sync(flow.queue, ^{
            nw_connection_set_state_changed_handler(flow.connection, nil);
            nw_connection_cancel(flow.connection);
            size_t read = atomic_load_explicit(&flow->readIndex, memory_order_relaxed);
            size_t write = atomic_load_explicit(&flow->writeIndex, memory_order_acquire);
            for (; read != write; read++) {
                dispatch_data_t data = (__bridge_transfer dispatch_data_t)flow->packets[read % RX_SLOTS];
                (void)data;
            }
            atomic_store_explicit(&flow->readIndex, write, memory_order_release);
        });
    }
}
