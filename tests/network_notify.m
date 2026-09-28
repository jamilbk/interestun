// Exercise notification failures deterministically without creating a utun.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <unistd.h>

static int injectedError;
static int calls;
static ssize_t testSend(int fd, const void *buffer, size_t length, int flags);
#define send testSend
#include "../src/platform/network_flow.m"
#undef send

static ssize_t testSend(int fd, const void *buffer, size_t length, int flags) {
    calls++;
    if (injectedError) {
        errno = injectedError;
        injectedError = 0;
        return -1;
    }
    return send(fd, buffer, length, flags);
}
static void ready(int kq, bool eof) {
    struct kevent event;
    struct timespec timeout = { .tv_sec = 1, .tv_nsec = 0 };
    assert(kevent(kq, NULL, 0, &event, 1, &timeout) == 1);
    assert(event.filter == EVFILT_READ);
    assert(((event.flags & EV_EOF) != 0) == eof);
}
// Verify retained data ownership, FIFO order across ring wrap, partial drains,
// the 128-message drain bound, and error propagation after the ring is empty.
static void ring_test(void) {
    @autoreleasepool {
        INFlow *flow = [INFlow new];
        flow->ringLock = (os_unfair_lock)OS_UNFAIR_LOCK_INIT;
        flow->rxWriter = flow->txWriter = -1;
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
        uint8_t storage[RX_WINDOW][PACKET_CAPACITY];
        uint8_t *buffers[RX_WINDOW];
        size_t lengths[RX_WINDOW];
        for (size_t i = 0; i < RX_WINDOW; i++) buffers[i] = storage[i];
        void *handle = (__bridge_retained void *)flow;
        for (uint64_t start = 0; start < RX_SLOTS;) {
            size_t limit = start == 0 ? 3 : RX_WINDOW;
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
        assert(in_flow_receive(handle, buffers, lengths, RX_WINDOW) == -EAGAIN);
        atomic_store(&flow->error, EIO);
        assert(in_flow_receive(handle, buffers, lengths, RX_WINDOW) == -EIO);
        in_flow_close(handle);
    }
}
int main(void) {
    ring_test();
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    assert(fcntl(pair[0], F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(pair[1], F_SETFL, O_NONBLOCK) == 0);
    int kq = kqueue();
    assert(kq >= 0);
    struct kevent registration;
    EV_SET(&registration, pair[1], EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    assert(kevent(kq, &registration, 1, NULL, 0, NULL) == 0);
    uint8_t buffer[1024];
    injectedError = EINTR;
    notify(pair[0]);
    assert(calls == 2);
    ready(kq, false);
    assert(recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT) == 1);

    memset(buffer, 0, sizeof(buffer));
    while (send(pair[0], buffer, sizeof(buffer), MSG_DONTWAIT) >= 0) {}
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    notify(pair[0]); // Already pending: EAGAIN must not close the channel.
    ready(kq, false);
    while (recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {}
    assert(errno == EAGAIN || errno == EWOULDBLOCK);
    notify(pair[0]);
    ready(kq, false);
    assert(recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT) == 1);

    injectedError = ENOBUFS;
    notify(pair[0]); // Unexpected failure must become readable EOF, not a stall.
    ready(kq, true);
    assert(recv(pair[1], buffer, sizeof(buffer), MSG_DONTWAIT) == 0);
    close(pair[0]);
    close(pair[1]);
    close(kq);
    puts("PASS ring ownership/wrap/partial drains; notification EINTR/full-channel/EOF");
    return 0;
}
