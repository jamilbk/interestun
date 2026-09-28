// Callback delivery remains serial; packet handoff uses a short ring lock.
// Rust never waits for the callback queue in the send/receive hot paths.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <errno.h>
#include <os/lock.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <unistd.h>

#define RX_SLOTS 1024
#define RX_WINDOW 128
#define RX_BATCH 128
#define TX_SLOTS 1024
#define PACKET_CAPACITY 2048

@interface INFlow : NSObject {
@public
    os_unfair_lock ringLock;
    dispatch_data_t packets[RX_SLOTS];
    size_t lengths[RX_SLOTS];
    size_t head, count, reserved;
    bool refillScheduled, notifyScheduled; // ringLock protects these and the ring.
    _Atomic(size_t) pending;
    _Atomic(int) error;
    _Atomic(bool) closing, ready;
    void *wakeContext;
    void (*wakeWorker)(void *, bool);
    void (*releaseContext)(void *);
}
@property nw_connection_t connection;
@property dispatch_queue_t queue;
- (void)refill;
- (void)scheduleRefill;
- (void)scheduleNotify;
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
- (void)scheduleNotify {
    os_unfair_lock_lock(&ringLock);
    bool schedule = !notifyScheduled && count != 0;
    if (schedule) notifyScheduled = true;
    os_unfair_lock_unlock(&ringLock);
    if (!schedule) return;
    // Run after callbacks already queued for this batch. No timer or minimum
    // packet threshold: a lone handshake/datagram is notified too.
    dispatch_async(self.queue, ^{
        os_unfair_lock_lock(&self->ringLock);
        self->notifyScheduled = false;
        bool queued = self->count != 0;
        os_unfair_lock_unlock(&self->ringLock);
        if (queued && !atomic_load_explicit(&self->closing, memory_order_acquire)) notify(self, false);
    });
}
- (void)scheduleRefill {
    os_unfair_lock_lock(&ringLock);
    bool schedule = !refillScheduled && reserved <= RX_WINDOW / 2 && count + reserved < RX_SLOTS;
    if (schedule) refillScheduled = true;
    os_unfair_lock_unlock(&ringLock);
    if (!schedule) return;
    dispatch_async(self.queue, ^{
        os_unfair_lock_lock(&self->ringLock);
        self->refillScheduled = false;
        os_unfair_lock_unlock(&self->ringLock);
        [self refill];
    });
}
- (void)refill {
    if (atomic_load_explicit(&closing, memory_order_acquire) ||
        atomic_load_explicit(&error, memory_order_acquire) ||
        !atomic_load_explicit(&ready, memory_order_acquire)) return;
    os_unfair_lock_lock(&ringLock);
    size_t n = MIN(RX_WINDOW - reserved, RX_SLOTS - count - reserved);
    reserved += n; // Reserve ring capacity for every outstanding callback.
    os_unfair_lock_unlock(&ringLock);
    if (!n) return;
    nw_connection_batch(self.connection, ^{
        for (size_t i = 0; i < n; i++) {
            nw_connection_receive_message(self.connection, ^(dispatch_data_t data, nw_content_context_t context, bool complete, nw_error_t e) {
                (void)context;
                if (atomic_load_explicit(&self->closing, memory_order_acquire)) return;
                size_t length = data ? dispatch_data_get_size(data) : 0;
                bool valid = !e && complete && length > 0 && length <= PACKET_CAPACITY;
                os_unfair_lock_lock(&self->ringLock);
                self->reserved--;
                bool wasEmpty = self->count == 0;
                if (valid) {
                    size_t slot = (self->head + self->count) % RX_SLOTS;
                    self->packets[slot] = data; // ARC retains immutable framework storage.
                    self->lengths[slot] = length;
                    self->count++;
                }
                os_unfair_lock_unlock(&self->ringLock);
                if (e) { fail(self, posix_error(e)); return; }
                if (valid && wasEmpty) [self scheduleNotify];
                [self scheduleRefill];

            });
        }
    });
}
@end

void *in_flow_open(const char *host, const char *port, const char *localHost,
                   const char *localPort, void *context, void (*wake)(void *, bool), void (*release)(void *)) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow->ringLock = (os_unfair_lock)OS_UNFAIR_LOCK_INIT;
        atomic_init(&flow->pending, 0);
        atomic_init(&flow->error, 0);
        atomic_init(&flow->closing, false);
        atomic_init(&flow->ready, false);
        flow->wakeContext = context;
        flow->wakeWorker = wake;
        flow->releaseContext = release;
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
        os_unfair_lock_lock(&flow->ringLock);
        size_t available = MIN(MIN(capacity, RX_BATCH), flow->count);
        for (size_t i = 0; i < available; i++) {
            size_t slot = flow->head;
            batch[i] = flow->packets[slot];
            flow->packets[slot] = nil;
            lengths[i] = flow->lengths[slot];
            flow->head = (slot + 1) % RX_SLOTS;
        }
        flow->count -= available;
        os_unfair_lock_unlock(&flow->ringLock);
        if (available) [flow scheduleRefill];
        // No staging-payload copy and no dispatch_sync: transfer retained data
        // references under the lock, then copy directly into Rust's cached slots.
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
            os_unfair_lock_lock(&flow->ringLock);
            for (size_t i = 0; i < RX_SLOTS; i++) flow->packets[i] = nil;
            flow->count = 0;
            os_unfair_lock_unlock(&flow->ringLock);
        });
    }
}
