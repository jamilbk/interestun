// Benchmark-only bridge. ARC keeps callbacks/data alive after cancellation or
// timeout. dispatch_data_create(DEFAULT) copies Rust buffers before returning;
// no asynchronous callback borrows Rust memory.
#import <Foundation/Foundation.h>
#import <Network/Network.h>
#include <errno.h>

@interface INConnection : NSObject
@property nw_connection_t connection;
@property dispatch_queue_t queue;
@property dispatch_semaphore_t ready;
@property int error;
@end
@implementation INConnection
@end

@interface INBatch : NSObject
@property dispatch_group_t group;
@property int error;
@end
@implementation INBatch
@end

void *in_nw_open(const char *host, const char *port, int *error) {
    @autoreleasepool {
        INConnection *owner = [INConnection new];
        owner.queue = dispatch_queue_create("interestun.network-bench", DISPATCH_QUEUE_SERIAL);
        owner.ready = dispatch_semaphore_create(0);
        nw_parameters_t parameters = nw_parameters_create_secure_udp(
            NW_PARAMETERS_DISABLE_PROTOCOL, NW_PARAMETERS_DEFAULT_CONFIGURATION);
        owner.connection = nw_connection_create(nw_endpoint_create_host(host, port), parameters);
        nw_connection_set_queue(owner.connection, owner.queue);
        __weak INConnection *weakOwner = owner;
        nw_connection_set_state_changed_handler(owner.connection, ^(nw_connection_state_t state, nw_error_t e) {
            INConnection *strongOwner = weakOwner;
            if (!strongOwner) return;
            if (state == nw_connection_state_ready || state == nw_connection_state_failed || state == nw_connection_state_waiting) {
                strongOwner.error = e ? nw_error_get_error_code(e) : 0;
                if (state != nw_connection_state_ready && !strongOwner.error) strongOwner.error = EIO;
                dispatch_semaphore_signal(strongOwner.ready);
            }
        });
        nw_connection_start(owner.connection);
        long timeout = dispatch_semaphore_wait(owner.ready, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC));
        // Read state on its queue, not concurrently with its handler.
        __block int connectionError = 0;
        dispatch_sync(owner.queue, ^{ connectionError = owner.error; });
        *error = timeout ? ETIMEDOUT : connectionError;
        if (*error) {
            nw_connection_cancel(owner.connection);
            return NULL;
        }
        char *description = nw_connection_copy_description(owner.connection);
        if (description) {
            fprintf(stderr, "Network.framework: %s\n", description);
            free(description);
        }
        return (__bridge_retained void *)owner;
    }
}

void *in_nw_submit(void *handle, const uint8_t *const *buffers, const size_t *lengths, size_t count) {
    @autoreleasepool {
        INConnection *owner = (__bridge INConnection *)handle;
        INBatch *batch = [INBatch new];
        batch.group = dispatch_group_create();
        // Enter everything before submission: completion cannot make the group
        // appear finished while the rest of this batch is still being enqueued.
        for (size_t i = 0; i < count; ++i) dispatch_group_enter(batch.group);
        nw_connection_batch(owner.connection, ^{
            for (size_t i = 0; i < count; ++i) {
                dispatch_data_t data = dispatch_data_create(buffers[i], lengths[i], NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
                nw_connection_send(owner.connection, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true, ^(nw_error_t error) {
                    if (error && !batch.error) batch.error = nw_error_get_error_code(error);
                    dispatch_group_leave(batch.group);
                });
            }
        });
        return (__bridge_retained void *)batch;
    }
}

// Consumes one batch handle, including on timeout. Remaining callbacks retain
// the batch until done. Success means content processed, not remote delivery.
int in_nw_wait(void *handle) {
    @autoreleasepool {
        INBatch *batch = (__bridge_transfer INBatch *)handle;
        if (dispatch_group_wait(batch.group, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) return ETIMEDOUT;
        return batch.error;
    }
}

void in_nw_close(void *handle) {
    @autoreleasepool {
        INConnection *owner = (__bridge_transfer INConnection *)handle;
        nw_connection_cancel(owner.connection);
    }
}
