#ifndef INTERESTUN_BRIDGE_H
#define INTERESTUN_BRIDGE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct InterestunSession InterestunSession;
typedef struct {
    const uint8_t *bytes;
    size_t len;
    uint32_t family;
} InterestunPacketView;

// Write is synchronous, but may retain the batch lease for Foundation objects.
// Each retain must be released once, after the last reference to its bytes.
typedef bool (*InterestunWrite)(void *, const InterestunPacketView *, size_t, const void *);
typedef void (*InterestunRelease)(void *);
bool interestun_ne_validate(const char *, uint32_t cipher, char **error);
// Queue inspection/tuning on the already-created utun; never creates an interface.
// Zero requests readback only. Returns owned JSON; free it with string_free.
char *interestun_ne_utun_options(const char *name, uint32_t receive_bytes, uint32_t pending, char **error);
// Consumes writer context on both success and failure. Cipher 0=AES, 1=ChaCha.
InterestunSession *interestun_ne_start(const char *, uint32_t cipher, uint32_t mtu,
    const char *name, void *context, InterestunWrite, InterestunRelease, char **error);
// Non-null local_addresses selects IPv4 Ethernet framing; comma-separated IPs.
// Consumes context on success and failure, just like interestun_ne_start.
InterestunSession *interestun_ne_start_flow(const char *, uint32_t cipher, uint32_t mtu,
    const char *name, const char *local_addresses, void *context, InterestunWrite, InterestunRelease, char **error);
// Duplicates the provider-owned utun descriptor. Do not also use packetFlow I/O.
InterestunSession *interestun_ne_start_utun(const char *, uint32_t cipher, const char *name, char **error);
// Provider serializes receive/tick/status/stop. At most 128 input views per call.
size_t interestun_ne_receive(InterestunSession *, const InterestunPacketView *, size_t);
bool interestun_ne_tick(InterestunSession *);
char *interestun_ne_status(InterestunSession *);
void interestun_ne_stop(InterestunSession *);
void interestun_ne_batch_retain(const void *);
void interestun_ne_batch_release(const void *);
void interestun_ne_string_free(char *);
#endif
