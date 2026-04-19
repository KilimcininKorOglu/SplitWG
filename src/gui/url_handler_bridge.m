// Tiny ObjC shim — installs an AppleEvent handler for the
// `kInternetEventClass / kAEGetURL` event pair (how LaunchServices
// delivers `x-splitwg://…` URLs to a running process). When the event
// fires we extract the URL string and hand it to the Rust callback
// registered via `splitwg_install_url_handler`.

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

// Rust-side callback signature: receives a UTF-8, NUL-terminated string.
// The shim owns the buffer; Rust must copy before returning.
typedef void (*splitwg_url_callback_t)(const char *url);

static splitwg_url_callback_t g_callback = NULL;

@interface SplitwgURLHandler : NSObject
- (void)handleURLEvent:(NSAppleEventDescriptor *)event
        withReplyEvent:(NSAppleEventDescriptor *)reply;
@end

@implementation SplitwgURLHandler
- (void)handleURLEvent:(NSAppleEventDescriptor *)event
        withReplyEvent:(NSAppleEventDescriptor *)reply {
    (void)reply;
    NSAppleEventDescriptor *direct =
        [event paramDescriptorForKeyword:keyDirectObject];
    NSString *urlStr = [direct stringValue];
    if (urlStr == nil) {
        return;
    }
    const char *utf8 = [urlStr UTF8String];
    if (utf8 == NULL) {
        return;
    }
    if (g_callback != NULL) {
        g_callback(utf8);
    }
}
@end

// ARC holds the handler object alive for the process lifetime via this
// static retain. Calling twice is a no-op — the second call replaces the
// callback but leaves the installed handler in place.
static SplitwgURLHandler *g_handler = nil;

void splitwg_install_url_handler(splitwg_url_callback_t cb) {
    g_callback = cb;
    if (g_handler != nil) {
        return;
    }
    g_handler = [[SplitwgURLHandler alloc] init];
    [[NSAppleEventManager sharedAppleEventManager]
        setEventHandler:g_handler
            andSelector:@selector(handleURLEvent:withReplyEvent:)
          forEventClass:kInternetEventClass
             andEventID:kAEGetURL];
}
