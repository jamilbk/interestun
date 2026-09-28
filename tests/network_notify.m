// Exercise retained message/signal ownership without creating a utun.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/platform/network_flow.m"

// Verify retained data ownership, FIFO order across ring wrap, partial drains,
// the 128-message drain bound, and error propagation after the ring is empty.
static void ring_test(void) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow->ringLock = (os_unfair_lock)OS_UNFAIR_LOCK_INIT;
        atomic_init(&flow->ready, false);
        atomic_init(&flow->closing, false);
        atomic_init(&flow->error, 0);
        atomic_init(&flow->pending, 0);
        flow.queue = dispatch_queue_create("test.network.ring", DISPATCH_QUEUE_SERIAL);
        flow->head = RX_SLOTS - 7;
        flow->count = RX_SLOTS;
        for (uint64_t i = 0; i < RX_SLOTS; i++) {
            size_t slot = (flow->head + i) % RX_SLOTS;
            flow->packets[slot] = dispatch_data_create(&i, sizeof(i), NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
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
        flow->ringLock = (os_unfair_lock)OS_UNFAIR_LOCK_INIT;
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
int main(void) {
    ring_test();
    signal_test();
    puts("PASS ring ownership/wrap/partial drains; signal direction/lifetime");
    return 0;
}
