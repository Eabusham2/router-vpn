#import <AppKit/AppKit.h>

@interface RouterVPNMenuBarBootstrap : NSObject
@property(nonatomic, strong) NSStatusItem *statusItem;
@property(nonatomic, strong) NSPanel *torPanel;
@property(nonatomic, strong) NSPopUpButton *torTransport;
@property(nonatomic, strong) NSPopUpButton *torKillSwitch;
@property(nonatomic, strong) NSTextField *torName;
@property(nonatomic, strong) NSTextView *torBridges;
@property(nonatomic, strong) NSTextField *torCapability;
@property(nonatomic, strong) NSTextField *torStatus;
@property(nonatomic, strong) NSDictionary<NSString *, NSDictionary *> *torCapabilities;
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
    RouterVPNMenuBarBootstrap *bootstrap = [self shared];
    [bootstrap installMenuBarItem];
    [bootstrap startVerifiedUpdateCheck];
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
    [menu addItemWithTitle:@"Tor Bridges…" action:@selector(showTorBridges:) keyEquivalent:@""];
    menu.itemArray.lastObject.target = self;
    [menu addItemWithTitle:@"Check for Updates" action:@selector(checkForUpdates:) keyEquivalent:@""];
    menu.itemArray.lastObject.target = self;
    [menu addItemWithTitle:@"Emergency Stop" action:@selector(emergencyStop:) keyEquivalent:@""];
    menu.itemArray.lastObject.target = self;
    [menu addItem:[NSMenuItem separatorItem]];
    [menu addItemWithTitle:@"Quit Router VPN" action:@selector(quitRouterVPN:) keyEquivalent:@"q"];
    menu.itemArray.lastObject.target = self;
    self.statusItem.menu = menu;
}

- (NSURL *)updateHelperURL {
    NSURL *root = NSBundle.mainBundle.bundleURL.URLByDeletingLastPathComponent;
    NSURL *candidate = [root URLByAppendingPathComponent:@"router-vpn-update" isDirectory:NO];
    if (![[NSFileManager defaultManager] isExecutableFileAtPath:candidate.path]) return nil;
    return candidate;
}

- (void)startVerifiedUpdateCheck {
    NSURL *helper = [self updateHelperURL];
    if (!helper) return;
    NSTask *task = [NSTask new];
    task.executableURL = helper;
    task.arguments = @[@"--download", @"--json"];
    task.currentDirectoryURL = helper.URLByDeletingLastPathComponent;
    NSMutableDictionary *environment = [NSProcessInfo.processInfo.environment mutableCopy];
    environment[@"ROUTER_VPN_UPDATE_LAUNCH"] = @"macos-native";
    task.environment = environment;
    NSFileHandle *nullHandle = [NSFileHandle fileHandleWithNullDevice];
    task.standardOutput = nullHandle;
    task.standardError = nullHandle;
    NSError *error = nil;
    if (![task launchAndReturnError:&error]) {
        NSLog(@"Router VPN update check could not start: %@", error.localizedDescription);
    }
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

- (NSURLSession *)localSession {
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.connectionProxyDictionary = @{};
    configuration.URLCache = nil;
    configuration.requestCachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
    return [NSURLSession sessionWithConfiguration:configuration];
}

- (void)performLocalRequest:(NSString *)path method:(NSString *)method body:(NSDictionary *)body completion:(void (^)(NSDictionary *json, NSString *errorText))completion {
    NSURL *url = [NSURL URLWithString:[@"http://127.0.0.1:8788" stringByAppendingString:path]];
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url];
    request.HTTPMethod = method;
    request.cachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
    request.timeoutInterval = 20.0;
    [request setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    if (body) {
        NSError *encodeError = nil;
        request.HTTPBody = [NSJSONSerialization dataWithJSONObject:body options:0 error:&encodeError];
        if (encodeError) { completion(nil, encodeError.localizedDescription); return; }
        [request setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    }
    [[[self localSession] dataTaskWithRequest:request completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
        NSString *errorText = nil;
        NSDictionary *json = nil;
        NSInteger status = [(NSHTTPURLResponse *)response statusCode];
        if (error) errorText = error.localizedDescription;
        else if (status < 200 || status >= 300) {
            errorText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] ?: [NSHTTPURLResponse localizedStringForStatusCode:status];
            errorText = [errorText stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        } else if (data.length) {
            id decoded = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
            if ([decoded isKindOfClass:NSDictionary.class]) json = decoded;
        }
        dispatch_async(dispatch_get_main_queue(), ^{ completion(json, errorText); });
    }] resume];
}

- (NSString *)selectedTorTransportID {
    NSArray<NSString *> *ids = @[@"obfs4", @"meek_lite", @"snowflake", @"webtunnel", @"custom"];
    NSInteger index = MAX(0, MIN(self.torTransport.indexOfSelectedItem, (NSInteger)ids.count - 1));
    return ids[index];
}

- (NSString *)selectedTorKillSwitch {
    NSArray<NSString *> *values = @[@"off", @"on-connect", @"always"];
    NSInteger index = MAX(0, MIN(self.torKillSwitch.indexOfSelectedItem, (NSInteger)values.count - 1));
    return values[index];
}

- (void)renderTorCapability {
    NSString *transport = [self selectedTorTransportID];
    NSDictionary *row = self.torCapabilities[transport];
    if (!row) { self.torCapability.stringValue = @"Checking platform support…"; return; }
    BOOL supported = [row[@"supported"] boolValue];
    BOOL strict = [row[@"strict_kill_switch"] boolValue];
    NSString *description = row[@"description"] ?: @"";
    NSString *reason = row[@"reason"] ?: @"";
    self.torCapability.stringValue = [NSString stringWithFormat:@"%@ • strict kill switch %@\n%@%@", supported ? @"Available" : @"Unavailable", strict ? @"supported" : @"not currently safe", description, reason.length ? [@"\nReason: " stringByAppendingString:reason] : @""];
    if (!strict && self.torKillSwitch.indexOfSelectedItem != 0) self.torStatus.stringValue = @"This transport uses dynamic CDN/STUN/WebRTC/bootstrap egress. Choose Kill switch Off until Router VPN has process-scoped PT firewall ownership.";
    else self.torStatus.stringValue = @"";
}

- (void)refreshTorCapabilities:(id)sender {
    self.torCapability.stringValue = @"Checking Tor transport support…";
    [self performLocalRequest:@"/api/tor-bridge/capabilities" method:@"GET" body:nil completion:^(NSDictionary *json, NSString *errorText) {
        if (errorText.length) { self.torCapability.stringValue = [@"Tor support check failed: " stringByAppendingString:errorText]; return; }
        NSMutableDictionary *mapped = [NSMutableDictionary new];
        NSArray *rows = [json[@"transports"] isKindOfClass:NSArray.class] ? json[@"transports"] : @[];
        for (NSDictionary *row in rows) { NSString *transportID = row[@"id"]; if ([transportID isKindOfClass:NSString.class]) mapped[transportID] = row; }
        self.torCapabilities = mapped;
        [self renderTorCapability];
    }];
}

- (void)torTransportChanged:(id)sender { [self renderTorCapability]; }

- (void)saveTorBridge:(id)sender {
    NSString *raw = self.torBridges.string ?: @"";
    NSMutableArray<NSString *> *lines = [NSMutableArray new];
    [raw enumerateLinesUsingBlock:^(NSString *line, BOOL *stop) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet];
        if (trimmed.length) [lines addObject:trimmed];
    }];
    if (!lines.count) { self.torStatus.stringValue = @"Paste at least one Tor bridge line."; return; }
    NSString *transport = [self selectedTorTransportID];
    NSDictionary *capability = self.torCapabilities[transport];
    if (capability && ![capability[@"supported"] boolValue]) { self.torStatus.stringValue = [NSString stringWithFormat:@"%@ is unavailable: %@", transport, capability[@"reason"] ?: @"required Tor helper is missing"]; return; }
    NSString *kill = [self selectedTorKillSwitch];
    if (capability && ![capability[@"strict_kill_switch"] boolValue] && ![kill isEqualToString:@"off"]) { self.torStatus.stringValue = @"Dynamic Tor transports require Kill switch Off until process-scoped PT egress filtering is implemented."; return; }
    NSDictionary *body = @{ @"name": [self.torName.stringValue stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet], @"transport": transport, @"bridges": lines, @"kill_switch_policy": kill };
    self.torStatus.stringValue = @"Validating and saving Tor node…";
    [self performLocalRequest:@"/api/tor-bridge/import" method:@"POST" body:body completion:^(NSDictionary *json, NSString *errorText) {
        if (errorText.length) { self.torStatus.stringValue = [@"Tor node rejected: " stringByAppendingString:errorText]; return; }
        NSDictionary *profile = [json[@"profile"] isKindOfClass:NSDictionary.class] ? json[@"profile"] : nil;
        NSString *name = [profile[@"name"] isKindOfClass:NSString.class] ? profile[@"name"] : @"Tor node";
        self.torStatus.stringValue = [NSString stringWithFormat:@"Saved %@. Return to Router VPN and select/connect it normally.", name];
    }];
}

- (void)showTorBridges:(id)sender {
    if (!self.torPanel) {
        NSPanel *panel = [[NSPanel alloc] initWithContentRect:NSMakeRect(0, 0, 720, 640) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable|NSWindowStyleMaskResizable backing:NSBackingStoreBuffered defer:NO];
        panel.title = @"Tor censorship circumvention"; panel.minSize = NSMakeSize(600, 520); panel.releasedWhenClosed = NO;
        NSStackView *root = [NSStackView stackViewWithViews:@[]]; root.orientation = NSUserInterfaceLayoutOrientationVertical; root.spacing = 10; root.edgeInsets = NSEdgeInsetsMake(18, 18, 18, 18); root.translatesAutoresizingMaskIntoConstraints = NO;
        [panel.contentView addSubview:root]; [NSLayoutConstraint activateConstraints:@[[root.leadingAnchor constraintEqualToAnchor:panel.contentView.leadingAnchor], [root.trailingAnchor constraintEqualToAnchor:panel.contentView.trailingAnchor], [root.topAnchor constraintEqualToAnchor:panel.contentView.topAnchor], [root.bottomAnchor constraintEqualToAnchor:panel.contentView.bottomAnchor]]];
        NSTextField *title = [NSTextField labelWithString:@"Tor bridges"]; title.font = [NSFont systemFontOfSize:24 weight:NSFontWeightBold]; [root addArrangedSubview:title];
        NSTextField *intro = [NSTextField wrappingLabelWithString:@"Choose how Tor gets through censorship: obfs4 disguises traffic and resists active probing; meek uses HTTPS/CDN-style fronts; Snowflake uses brokers plus short-lived volunteer WebRTC proxies; WebTunnel resembles ordinary HTTPS web traffic. Auto / Custom accepts validated Tor-issued lines from recognized families. Tor's proved circuit—not homemade XOR—is the encrypted final path."]; intro.textColor = NSColor.secondaryLabelColor; [root addArrangedSubview:intro];
        self.torName = [NSTextField textFieldWithString:@""]; self.torName.placeholderString = @"Node name (optional)"; [root addArrangedSubview:self.torName];
        self.torTransport = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO]; [self.torTransport addItemsWithTitles:@[@"obfs4", @"meek", @"Snowflake", @"WebTunnel", @"Auto / Custom"]]; self.torTransport.target = self; self.torTransport.action = @selector(torTransportChanged:);
        self.torKillSwitch = [[NSPopUpButton alloc] initWithFrame:NSZeroRect pullsDown:NO]; [self.torKillSwitch addItemsWithTitles:@[@"Kill switch Off", @"On connect", @"Always / strict"]]; self.torKillSwitch.target = self; self.torKillSwitch.action = @selector(torTransportChanged:);
        NSGridView *grid = [NSGridView gridViewWithViews:@[@[[NSTextField labelWithString:@"Transport"], self.torTransport], @[[NSTextField labelWithString:@"Kill switch"], self.torKillSwitch]]]; grid.rowSpacing = 6; grid.columnSpacing = 10; [root addArrangedSubview:grid];
        NSTextField *bridgeLabel = [NSTextField labelWithString:@"Tor bridge lines — one per line"]; bridgeLabel.font = [NSFont systemFontOfSize:14 weight:NSFontWeightSemibold]; [root addArrangedSubview:bridgeLabel];
        self.torBridges = [NSTextView new]; self.torBridges.editable = YES; self.torBridges.selectable = YES; self.torBridges.font = [NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular]; self.torBridges.textContainerInset = NSMakeSize(8,8);
        NSScrollView *scroll = [NSScrollView new]; scroll.hasVerticalScroller = YES; scroll.autohidesScrollers = YES; scroll.borderType = NSBezelBorder; scroll.documentView = self.torBridges; [[scroll.heightAnchor constraintGreaterThanOrEqualToConstant:190] setActive:YES]; [root addArrangedSubview:scroll];
        NSTextField *hint = [NSTextField wrappingLabelWithString:@"Paste current bridge lines from Tor / your trusted bridge source. Router VPN accepts only obfs4, meek_lite, Snowflake, and WebTunnel syntax; profile data cannot inject ClientTransportPlugin commands, executable paths, or arbitrary torrc directives."]; hint.textColor = NSColor.secondaryLabelColor; [root addArrangedSubview:hint];
        self.torCapability = [NSTextField wrappingLabelWithString:@"Checking Tor transport support…"]; self.torCapability.textColor = NSColor.secondaryLabelColor; [root addArrangedSubview:self.torCapability];
        self.torStatus = [NSTextField wrappingLabelWithString:@""]; self.torStatus.textColor = NSColor.secondaryLabelColor; [root addArrangedSubview:self.torStatus];
        NSStackView *buttons = [NSStackView stackViewWithViews:@[]]; buttons.orientation = NSUserInterfaceLayoutOrientationHorizontal; buttons.spacing = 8;
        NSButton *save = [NSButton buttonWithTitle:@"Save Tor node" target:self action:@selector(saveTorBridge:)]; save.bezelStyle = NSBezelStyleRounded;
        NSButton *refresh = [NSButton buttonWithTitle:@"Refresh support" target:self action:@selector(refreshTorCapabilities:)]; refresh.bezelStyle = NSBezelStyleRounded;
        NSButton *close = [NSButton buttonWithTitle:@"Close" target:panel action:@selector(close)]; close.bezelStyle = NSBezelStyleRounded;
        [buttons addArrangedSubview:save]; [buttons addArrangedSubview:refresh]; [buttons addArrangedSubview:[NSView new]]; [buttons addArrangedSubview:close]; [root addArrangedSubview:buttons];
        self.torPanel = panel;
    }
    [self refreshTorCapabilities:nil];
    [self.torPanel center]; [self.torPanel makeKeyAndOrderFront:nil]; [NSApp activateIgnoringOtherApps:YES];
}

- (void)checkForUpdates:(id)sender {
    [self startVerifiedUpdateCheck];
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