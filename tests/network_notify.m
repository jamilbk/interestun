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

#include "../src/platform/network_flow.m"

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
    ring_test();
    signal_test();
    concurrent_ring_test();
    #ifdef IN_NETWORK_MULTIPLE
    grouped_receive_test();
    close_mid_batch_test();
    #endif
    puts("PASS Network.framework ring ownership, wrap, partial drains, concurrent producer/consumer, and lifetime");
    return 0;
}
