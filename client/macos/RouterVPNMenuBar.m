#import <AppKit/AppKit.h>

@interface RouterVPNMenuBarBootstrap : NSObject
@property(nonatomic, strong) NSStatusItem *statusItem;
@end

@implementation RouterVPNMenuBarBootstrap

+ (instancetype)shared {
    static RouterVPNMenuBarBootstrap *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{ shared = [RouterVPNMenuBarBootstrap new]; });
    return shared;
}

+ (void)load {
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(routerVPNDidFinishLaunching:)
                                                 name:NSApplicationDidFinishLaunchingNotification
                                               object:nil];
}

+ (void)routerVPNDidFinishLaunching:(NSNotification *)note {
    [[self shared] installMenuBarItem];
}

- (void)installMenuBarItem {
    if (self.statusItem) return;
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
    NSStatusBarButton *button = self.statusItem.button;
    if (button) {
        NSImage *image = NSApp.applicationIconImage;
        image.size = NSMakeSize(18.0, 18.0);
        button.image = image;
        button.toolTip = @"Router VPN";
    }

    NSMenu *menu = [NSMenu new];
    [menu addItemWithTitle:@"Open Router VPN" action:@selector(showRouterVPN:) keyEquivalent:@""];
    menu.itemArray.lastObject.target = self;
    [menu addItemWithTitle:@"Emergency Stop" action:@selector(emergencyStop:) keyEquivalent:@""];
    menu.itemArray.lastObject.target = self;
    [menu addItem:[NSMenuItem separatorItem]];
    [menu addItemWithTitle:@"Quit Router VPN" action:@selector(quitRouterVPN:) keyEquivalent:@"q"];
    menu.itemArray.lastObject.target = self;
    self.statusItem.menu = menu;
}

- (NSWindow *)routerVPNWindow {
    for (NSWindow *window in NSApp.windows) {
        if ([window.title isEqualToString:@"Router VPN"]) return window;
    }
    return NSApp.windows.firstObject;
}

- (void)showRouterVPN:(id)sender {
    NSWindow *window = [self routerVPNWindow];
    [window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)emergencyStop:(id)sender {
    NSURL *url = [NSURL URLWithString:@"http://127.0.0.1:8788/api/emergency-stop"];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = @"POST";
    [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    request.HTTPBody = [@"{}" dataUsingEncoding:NSUTF8StringEncoding];
    request.cachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
    request.timeoutInterval = 3.0;
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.connectionProxyDictionary = @{};
    [[[NSURLSession sessionWithConfiguration:configuration] dataTaskWithRequest:request] resume];
}

- (void)quitRouterVPN:(id)sender {
    [NSApp terminate:nil];
}

@end
