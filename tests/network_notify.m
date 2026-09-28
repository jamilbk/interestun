// Exercise retained message/signal ownership without creating a utun.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sched.h>
#include <time.h>

static void test_send(nw_connection_t, dispatch_data_t, nw_content_context_t, bool, nw_connection_send_completion_t);
static void test_batch(nw_connection_t, dispatch_block_t);
static nw_error_domain_t test_error_domain(nw_error_t error) { assert(error); return nw_error_domain_posix; }
static int test_error_code(nw_error_t error) { assert(error); return ENOBUFS; }
#define nw_connection_send test_send
#define nw_connection_batch test_batch
#define nw_error_get_error_domain test_error_domain
#define nw_error_get_error_code test_error_code
#define IN_NETWORK_BENCH
#include "../src/platform/network_flow.m"
#undef nw_connection_send
#undef nw_connection_batch
#undef nw_error_get_error_domain
#undef nw_error_get_error_code

static nw_connection_send_completion_t sentCallbacks[TX_SLOTS];
static dispatch_data_t sentData[TX_SLOTS];
static size_t submitted;
static dispatch_queue_t completionQueue;
static void test_send(nw_connection_t connection, dispatch_data_t data, nw_content_context_t context,
                      bool complete, nw_connection_send_completion_t callback) {
    (void)connection;
    assert(context == NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT && complete && callback);
    if (completionQueue) {
        dispatch_async(completionQueue, ^{
            assert(dispatch_data_get_size(data) == 1);
            callback(nil);
        });
        return;
    }
    assert(submitted < TX_SLOTS);
    sentCallbacks[submitted] = callback;
    sentData[submitted++] = data;
}
static void test_batch(nw_connection_t connection, dispatch_block_t block) {
    (void)connection;
    block(); // The public API invokes this synchronously.
}

// Verify retained data ownership, FIFO order across ring wrap, partial drains,
// the 128-message drain bound, and error propagation after the ring is empty.
static void ring_test(void) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        atomic_init(&flow->ready, false);
        atomic_init(&flow->closing, false);
        atomic_init(&flow->error, 0);
        atomic_init(&flow->pending, 0);
        flow.queue = dispatch_queue_create("test.network.ring", DISPATCH_QUEUE_SERIAL);
        atomic_init(&flow->readIndex, RX_SLOTS - 7);
        atomic_init(&flow->writeIndex, 2 * RX_SLOTS - 7);
        for (uint64_t i = 0; i < RX_SLOTS; i++) {
            size_t slot = (RX_SLOTS - 7 + i) % RX_SLOTS;
            flow->packets[slot] = (__bridge_retained void *)dispatch_data_create(&i, sizeof(i), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
            flow->lengths[slot] = sizeof(i);
        }
        uint8_t storage[RX_BATCH][PACKET_CAPACITY];
        uint8_t *buffers[RX_BATCH];
        size_t lengths[RX_BATCH];
        for (size_t i = 0; i < RX_BATCH; i++) buffers[i] = storage[i];
        void *handle = (__bridge_retained void *)flow;
        assert(in_flow_tx_pending(handle) == -EAGAIN);
        for (uint64_t start = 0; start < RX_SLOTS;) {
            size_t limit = start == 0 ? 3 : RX_BATCH;
            int n = in_flow_receive(handle, buffers, lengths, limit);
            assert(n == (int)MIN(limit, RX_SLOTS - start));
            for (int i = 0; i < n; i++) {
                uint64_t value;
                assert(lengths[i] == sizeof(value));
                memcpy(&value, storage[i], sizeof(value));
                assert(value == start + i);
            }
            start += n;
        }
        assert(in_flow_receive(handle, buffers, lengths, RX_BATCH) == -EAGAIN);
        atomic_store(&flow->error, EIO);
        assert(in_flow_receive(handle, buffers, lengths, RX_BATCH) == -EIO);
        in_flow_close(handle);
    }
}
typedef struct { unsigned rx, tx, released; } SignalCounts;
static void wakeSignal(void *context, bool tx) {
    SignalCounts *counts = context;
    if (tx) counts->tx++; else counts->rx++;
}
static void releaseSignal(void *context) { ((SignalCounts *)context)->released++; }

// Exercise actual submission with delayed, shuffled completions. All accepted
// payloads must remain owned after the caller recycles its input. Cancellation
// must retain the wake context until the final outstanding callback is freed.
static void send_test(void) {
    SignalCounts counts = {0};
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow.queue = dispatch_queue_create("test.network.send", DISPATCH_QUEUE_SERIAL);
        flow->wakeContext = &counts;
        flow->wakeWorker = wakeSignal;
        flow->releaseContext = releaseSignal;
        atomic_store(&flow->ready, true);
        uint8_t input[128];
        const uint8_t *buffers[128];
        size_t lengths[128];
        for (size_t i = 0; i < 128; i++) {
            input[i] = (uint8_t)i;
            buffers[i] = &input[i];
            lengths[i] = 1;
        }
        void *handle = (__bridge_retained void *)flow;
        assert(in_flow_send(handle, buffers, lengths, 0) == 0);
        assert(in_flow_send(handle, buffers, lengths, 129) == -EINVAL);
        // Fill with irregular groups, including a partial accepted prefix.
        for (size_t i = 0; i < 10; i++) assert(in_flow_send(handle, buffers, lengths, 100) == 100);
        assert(in_flow_send(handle, buffers, lengths, 100) == 24);
        assert(in_flow_send(handle, buffers, lengths, 1) == -EAGAIN);
        assert(atomic_load(&flow->pending) == TX_SLOTS);
        assert(in_flow_tx_pending(handle) == TX_SLOTS);
        memset(input, 255, sizeof(input));
        for (size_t i = 0; i < submitted; i++) {
            dispatch_data_apply(sentData[i], ^bool(dispatch_data_t region, size_t offset, const void *data, size_t size) {
                (void)region;
                assert(offset == 0 && size == 1 && *(const uint8_t *)data == i % 100);
                return true;
            });
        }
        // The last submitted datagram completing does not fence earlier sends.
        sentCallbacks[TX_SLOTS - 1](nil);
        sentCallbacks[TX_SLOTS - 1] = nil;
        assert(atomic_load(&flow->pending) > 0);
        for (size_t i = TX_SLOTS - 1; i-- > 0;) {
            sentCallbacks[i](nil);
            sentCallbacks[i] = nil;
            sentData[i] = nil;
        }
        sentData[TX_SLOTS - 1] = nil;
        assert(atomic_load(&flow->pending) == 0 && counts.tx >= 1);
        assert(in_flow_tx_pending(handle) == 0);
        INTxStats stats;
        in_flow_tx_stats(handle, &stats);
        assert(stats.accepted == TX_SLOTS && stats.blocked == 1 && stats.partial == 1);
        submitted = 0;
        assert(in_flow_send(handle, buffers, lengths, 2) == 2);
        nw_error_t error = (nw_error_t)[NSObject new];
        sentCallbacks[1](error);
        sentCallbacks[1] = nil;
        assert(atomic_load(&flow->error) == ENOBUFS);
        assert(in_flow_tx_pending(handle) == -ENOBUFS);
        assert(in_flow_send(handle, buffers, lengths, 1) == -ENOBUFS);
        unsigned wakes = counts.tx;
        flow = nil;
        in_flow_close(handle);
        assert(counts.released == 0);
        sentCallbacks[0](error);
        assert(counts.tx == wakes); // No worker wake after closing.
        sentCallbacks[0] = nil;
        sentData[0] = nil;
        sentData[1] = nil;
        submitted = 0;
    }
    assert(counts.released == 1);
}

static void wakeSemaphore(void *context, bool tx) {
    if (tx) dispatch_semaphore_signal((__bridge dispatch_semaphore_t)context);
}
static void concurrent_send_test(void) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        dispatch_queue_t queue = dispatch_queue_create("test.network.completions", DISPATCH_QUEUE_SERIAL);
        flow.queue = queue;
        completionQueue = queue;
        dispatch_semaphore_t signal = dispatch_semaphore_create(0);
        flow->wakeContext = (__bridge void *)signal;
        flow->wakeWorker = wakeSemaphore;
        atomic_store(&flow->ready, true);
        uint8_t value = 1;
        const uint8_t *buffers[128];
        size_t lengths[128];
        for (size_t i = 0; i < 128; i++) { buffers[i] = &value; lengths[i] = 1; }
        void *handle = (__bridge_retained void *)flow;
        // Lone datagrams must return their credits without a full batch or a
        // retry timer, across many credit-window wraps.
        for (size_t i = 0; i < 1001; i++) {
            assert(in_flow_send(handle, buffers, lengths, 1) == 1);
            dispatch_sync(queue, ^{});
            assert(atomic_load(&flow->pending) == 0);
        }
        dispatch_suspend(queue);
        bool suspended = true;
        const size_t total = 100003;
        uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 10 * NSEC_PER_SEC;
        for (size_t sent = 0; sent < total;) {
            assert(clock_gettime_nsec_np(CLOCK_MONOTONIC) < deadline);
            int n = in_flow_send(handle, buffers, lengths, MIN(128, total - sent));
            if (n == -EAGAIN) {
                if (suspended) { dispatch_resume(queue); suspended = false; }
                // No retry timer: the full-window transition must wake us.
                assert(dispatch_semaphore_wait(signal, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0);
            } else {
                assert(n > 0);
                sent += (size_t)n;
            }
            assert(atomic_load(&flow->pending) <= TX_SLOTS);
        }
        assert(!suspended);
        dispatch_sync(queue, ^{});
        assert(atomic_load(&flow->pending) == 0);
        INTxStats stats;
        in_flow_tx_stats(handle, &stats);
        assert(stats.accepted == total + 1001 && stats.blocked > 0 && stats.wakes > 0);
        completionQueue = nil;
        __weak INFlow *weak = flow;
        flow = nil;
        in_flow_close(handle);
        assert(!weak); // Close also releases an idle flow.
    }
}
static void signal_test(void) {
    SignalCounts counts = {0};
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow->wakeContext = &counts;
        flow->wakeWorker = wakeSignal;
        flow->releaseContext = releaseSignal;
        flow.queue = dispatch_queue_create("test.network.signals", DISPATCH_QUEUE_SERIAL);
        atomic_init(&flow->closing, false);
        notify(flow, false);
        notify(flow, true);
        assert(counts.rx == 1 && counts.tx == 1 && counts.released == 0);
        void *handle = (__bridge_retained void *)flow;
        flow = nil;
        in_flow_close(handle);
    }
    assert(counts.released == 1);
}

// Exercise release/acquire publication against a concurrent consumer, including
// groups crossing the end of the ring and pressure at its exact capacity.
static void concurrent_ring_test(void) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow.queue = dispatch_queue_create("test.network.producer", DISPATCH_QUEUE_SERIAL);
        dispatch_group_t finished = dispatch_group_create();
        const size_t total = 100000;
        dispatch_group_async(finished, flow.queue, ^{
            for (size_t next = 0; next < total;) {
                size_t read = atomic_load_explicit(&flow->readIndex, memory_order_acquire);
                size_t n = MIN(MIN((next % 127) + 1, RX_SLOTS - (next - read)), total - next);
                if (!n) { sched_yield(); continue; }
                for (size_t i = 0; i < n; i++) {
                    uint64_t value = next + i;
                    size_t slot = value % RX_SLOTS;
                    flow->packets[slot] = (__bridge_retained void *)dispatch_data_create(&value, sizeof(value), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                    flow->lengths[slot] = sizeof(value);
                }
                next += n;
                atomic_store_explicit(&flow->writeIndex, next, memory_order_release);
            }
        });
        uint8_t storage[RX_BATCH][PACKET_CAPACITY];
        uint8_t *buffers[RX_BATCH];
        size_t lengths[RX_BATCH];
        for (size_t i = 0; i < RX_BATCH; i++) buffers[i] = storage[i];
        void *handle = (__bridge_retained void *)flow;
        uint64_t deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC) + 10 * NSEC_PER_SEC;
        for (uint64_t expected = 0; expected < total;) {
            assert(clock_gettime_nsec_np(CLOCK_MONOTONIC) < deadline);
            int n = in_flow_receive(handle, buffers, lengths, RX_BATCH);
            if (n == -EAGAIN) { sched_yield(); continue; }
            assert(n > 0);
            for (int i = 0; i < n; i++) {
                uint64_t value;
                memcpy(&value, storage[i], sizeof(value));
                assert(lengths[i] == sizeof(value) && value == expected++);
            }
        }
        assert(dispatch_group_wait(finished, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
        in_flow_close(handle);
    }
}

#ifdef IN_NETWORK_MULTIPLE
static nw_connection_receive_completion_t pendingReceive;
static void fake_receive_multiple(nw_connection_t connection, uint32_t minimum,
                                  uint32_t maximum, nw_connection_receive_completion_t callback) {
    (void)connection;
    assert(minimum == 1 && maximum > 0 && maximum <= RX_WINDOW);
    assert(!pendingReceive);
    pendingReceive = callback;
}
// One publication/wakeup per group, full-ring backpressure, and refill when
// the consumer frees less than a full receive window. Invalid UDP sizes must
// not strand the request or use a ring slot.
static void grouped_receive_test(void) {
    SignalCounts counts = {0};
    SignalCounts *observed = &counts;
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow.queue = dispatch_queue_create("test.network.groups", DISPATCH_QUEUE_SERIAL);
        flow->wakeContext = &counts;
        flow->wakeWorker = wakeSignal;
        flow->receiveMultiple = fake_receive_multiple;
        atomic_store(&flow->ready, true);
        dispatch_sync(flow.queue, ^{
            [flow refill];
            for (size_t group = 0; group < RX_SLOTS / RX_WINDOW; group++) {
                nw_connection_receive_completion_t callback = pendingReceive;
                pendingReceive = nil;
                assert(callback);
                for (size_t i = 0; i < RX_WINDOW; i++) {
                    uint64_t value = group * RX_WINDOW + i;
                    dispatch_data_t data = dispatch_data_create(&value, sizeof(value), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                    assert(atomic_load(&flow->writeIndex) == group * RX_WINDOW);
                    callback(data, nil, i == RX_WINDOW - 1, nil);
                }
                assert(observed->rx == group + 1);
            }
            assert(!pendingReceive && atomic_load(&flow->reserved) == 0);
        });
        uint8_t storage[PACKET_CAPACITY], *buffer = storage;
        size_t length;
        void *handle = (__bridge_retained void *)flow;
        assert(in_flow_receive(handle, &buffer, &length, 1) == 1);
        dispatch_sync(flow.queue, ^{
            assert(pendingReceive && atomic_load(&flow->reserved) == 1);
            nw_connection_receive_completion_t callback = pendingReceive;
            pendingReceive = nil;
            uint8_t oversized[PACKET_CAPACITY + 1] = {0};
            callback(dispatch_data_create(oversized, sizeof(oversized), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT), nil, false, nil);
            callback(dispatch_data_empty, nil, false, nil);
            uint64_t value = RX_SLOTS;
            callback(dispatch_data_create(&value, sizeof(value), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT), nil, true, nil);
            assert(!pendingReceive && observed->rx == RX_SLOTS / RX_WINDOW + 1);
            assert(atomic_load(&flow->writeIndex) == RX_SLOTS + 1);
        });
        in_flow_close(handle);
    }
}
// Closing may be requested from Rust between two callbacks belonging to one
// receive group. Its unpublished references must also be released exactly once.
static void close_mid_batch_test(void) {
    SignalCounts counts = {0};
    __block unsigned destroyed = 0;
    dispatch_queue_t queue = dispatch_queue_create("test.network.cancel", DISPATCH_QUEUE_SERIAL);
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow.queue = queue;
        flow->wakeContext = &counts;
        flow->releaseContext = releaseSignal;
        flow->receiveMultiple = fake_receive_multiple;
        atomic_store(&flow->ready, true);
        [flow refill];
        assert(pendingReceive);
        uint64_t value = 42;
        dispatch_data_t data = dispatch_data_create(&value, sizeof(value), queue, ^{ destroyed++; });
        pendingReceive(data, nil, false, nil);
        data = nil;
        assert(atomic_load(&flow->writeIndex) == 0);
        void *handle = (__bridge_retained void *)flow;
        flow = nil;
        in_flow_close(handle);
        assert(counts.released == 0);
        pendingReceive(nil, nil, true, nil);
        pendingReceive = nil;
    }
    dispatch_sync(queue, ^{});
    assert(destroyed == 1 && counts.released == 1);
}
#endif
int main(void) {
    send_test();
    concurrent_send_test();
    ring_test();
    signal_test();
    concurrent_ring_test();
    #ifdef IN_NETWORK_MULTIPLE
    grouped_receive_test();
    close_mid_batch_test();
    #endif
    puts("PASS Network.framework TX ownership, errors, credits, wakeups, cancellation; RX ring and lifetime");
    return 0;
}
