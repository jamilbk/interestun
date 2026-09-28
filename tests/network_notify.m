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
int main(void) {
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
    puts("PASS notification EINTR retry, full-channel coalescing, and error EOF");
    return 0;
}
