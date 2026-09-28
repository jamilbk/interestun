// Validate the private receive_multiple ABI on the host OS without utun/root.
// This tests datagram boundaries, the last-in-group flag, a lone datagram, and
// cancellation. It is a correctness fixture, not a loopback performance test.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <arpa/inet.h>
#include <assert.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <unistd.h>

typedef void (*ReceiveMultiple)(nw_connection_t, uint32_t, uint32_t, nw_connection_receive_completion_t);
static void wait_for(dispatch_semaphore_t sem) {
    assert(dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC)) == 0);
}
int main(void) {
    @autoreleasepool {
        ReceiveMultiple receive = (ReceiveMultiple)dlsym(RTLD_DEFAULT, "nw_connection_receive_multiple");
        if (!receive) {
            fputs("SKIP: private receive_multiple SPI unavailable on this OS\n", stderr);
            return 77;
        }
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        assert(fd >= 0);
        struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
        assert(bind(fd, (struct sockaddr *)&address, sizeof(address)) == 0);
        socklen_t addressLength = sizeof(address);
        assert(getsockname(fd, (struct sockaddr *)&address, &addressLength) == 0);
        struct timeval timeout = {.tv_sec = 5};
        assert(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
        char port[10];
        snprintf(port, sizeof(port), "%u", ntohs(address.sin_port));
        dispatch_queue_t queue = dispatch_queue_create("test.network.multiple", DISPATCH_QUEUE_SERIAL);
        dispatch_semaphore_t ready = dispatch_semaphore_create(0);
        nw_parameters_t parameters = nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        nw_connection_t connection = nw_connection_create(nw_endpoint_create_host("127.0.0.1", port), parameters);
        nw_connection_set_queue(connection, queue);
        nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
            assert(state != nw_connection_state_failed && state != nw_connection_state_waiting);
            assert(!error);
            if (state == nw_connection_state_ready) dispatch_semaphore_signal(ready);
        });
        nw_connection_start(connection);
        wait_for(ready);
        uint8_t bytes[4096] = {7};
        nw_connection_send(connection, dispatch_data_create(bytes, 1, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT), NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) { assert(!error); });
        struct sockaddr_in source;
        socklen_t sourceLength = sizeof(source);
        assert(recvfrom(fd, bytes, sizeof(bytes), 0, (struct sockaddr *)&source, &sourceLength) == 1);
        static const size_t sizes[] = {1, 64, 1420, 4096, 32, 128, 256, 1024, 7};
        const size_t count = sizeof(sizes) / sizeof(sizes[0]);
        // Queue enough datagrams to cross our requested maximum of four.
        for (size_t i = 0; i < count; i++) {
            memset(bytes, (int)i, sizes[i]);
            assert(sendto(fd, bytes, sizes[i], 0, (struct sockaddr *)&source, sourceLength) == (ssize_t)sizes[i]);
        }
        dispatch_semaphore_t received = dispatch_semaphore_create(0);
        __block size_t total = 0;
        while (total < count) {
            __block unsigned callbacks = 0;
            __block bool ended = false;
            receive(connection, 1, 4, ^(dispatch_data_t data, nw_content_context_t context, bool last, nw_error_t error) {
                (void)context;
                assert(!error && !ended && total < count && ++callbacks <= 4);
                assert(dispatch_data_get_size(data) == sizes[total]);
                dispatch_data_apply(data, ^bool(dispatch_data_t region, size_t offset, const void *buffer, size_t size) {
                    (void)region; (void)offset;
                    for (size_t j = 0; j < size; j++) assert(((const uint8_t *)buffer)[j] == total);
                    return true;
                });
                total++;
                if (last) { ended = true; dispatch_semaphore_signal(received); }
            });
            wait_for(received);
            dispatch_sync(queue, ^{});
            assert(ended && callbacks > 0);
        }
        // Minimum one must deliver without waiting for the rest of the window.
        receive(connection, 1, 256, ^(dispatch_data_t data, nw_content_context_t context, bool last, nw_error_t error) {
            (void)context;
            assert(!error && last && dispatch_data_get_size(data) == 1);
            dispatch_semaphore_signal(received);
        });
        assert(sendto(fd, bytes, 1, 0, (struct sockaddr *)&source, sourceLength) == 1);
        wait_for(received);
        receive(connection, 1, 256, ^(dispatch_data_t data, nw_content_context_t context, bool last, nw_error_t error) {
            (void)context;
            assert(error && last && (!data || dispatch_data_get_size(data) == 0));
            dispatch_semaphore_signal(received);
        });
        nw_connection_cancel(connection);
        wait_for(received);
        dispatch_sync(queue, ^{});
        close(fd);
    }
    puts("PASS private receive_multiple host ABI: boundaries, batch limit, lone packet, cancellation");
    return 0;
}
