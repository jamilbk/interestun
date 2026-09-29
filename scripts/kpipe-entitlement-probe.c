// Read-only signature probe. No socket, interface, channel, or helper calls.
// Build: xcrun clang -O2 -Wall -Wextra -Werror scripts/kpipe-entitlement-probe.c \
//   -framework Security -framework CoreFoundation -o /tmp/kpipe-entitlement-probe
// These Security functions are private SPI. A true entitlement readback alone
// is NOT proof that priv_check_cred(12001) or a subsequent ring attachment works.
#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateFromSelf(CFAllocatorRef);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef,CFStringRef,CFErrorRef *);
extern bool SecTaskEntitlementsValidated(SecTaskRef);
extern int csops(pid_t,unsigned int,void *,size_t);
int main(void) {
 SecTaskRef task=SecTaskCreateFromSelf(kCFAllocatorDefault);
 if(!task)return 2;
 CFErrorRef error=NULL;
 CFTypeRef value=SecTaskCopyValueForEntitlement(task,CFSTR("com.apple.private.skywalk.register-kernel-pipe"),&error);
 uint32_t flags=0; int rc=csops(getpid(),0,&flags,sizeof(flags));
 printf("{\"pid\":%d,\"uid\":%d,\"kernel_pipe_entitlement\":%s,\"entitlements_validated\":%s,\"csops_rc\":%d,\"csflags\":%u,\"cferror\":%ld}\n",getpid(),getuid(),value&&CFEqual(value,kCFBooleanTrue)?"true":"false",SecTaskEntitlementsValidated(task)?"true":"false",rc,flags,error?(long)CFErrorGetCode(error):0);
 if(value)CFRelease(value);if(error)CFRelease(error);CFRelease(task);return 0;
}
