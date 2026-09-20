#import "RVPNTunnelTCPConnection.h"
#import <NetworkExtension/NetworkExtension.h>
#import <arpa/inet.h>

@interface RVPNTunnelTCPConnection ()
@property (nonatomic, strong) NWTCPConnection *connection;
@end

@implementation RVPNTunnelTCPConnection

- (nullable instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                                    host:(NSString *)host
                                    port:(uint16_t)port {
    // Never let this credential-bearing channel perform hostname resolution.
    struct in_addr v4;
    struct in6_addr v6;
    const char *literal = host.UTF8String;
    if (!provider || port == 0 || !literal ||
        (inet_pton(AF_INET, literal, &v4) != 1 && inet_pton(AF_INET6, literal, &v6) != 1)) {
        return nil;
    }
    self = [super init];
    if (self) {
        NWHostEndpoint *endpoint = [NWHostEndpoint endpointWithHostname:host
                                                                 port:[NSString stringWithFormat:@"%u", (unsigned)port]];
        // This is deliberately NOT NEProvider's createTCPConnectionToEndpoint:
        // that API creates an outer-network connection and can bypass the VPN.
        _connection = [provider createTCPConnectionThroughTunnelToEndpoint:endpoint
                                                               enableTLS:NO
                                                           TLSParameters:nil
                                                                delegate:nil];
        if (!_connection) { return nil; }
    }
    return self;
}

+ (NSSet<NSString *> *)keyPathsForValuesAffectingState {
    return [NSSet setWithObject:@"connection.state"];
}

- (RVPNTunnelTCPConnectionState)state {
    switch (self.connection.state) {
        case NWTCPConnectionStateConnecting: return RVPNTunnelTCPConnectionStateConnecting;
        case NWTCPConnectionStateWaiting: return RVPNTunnelTCPConnectionStateWaiting;
        case NWTCPConnectionStateConnected: return RVPNTunnelTCPConnectionStateConnected;
        case NWTCPConnectionStateDisconnected: return RVPNTunnelTCPConnectionStateDisconnected;
        case NWTCPConnectionStateCancelled: return RVPNTunnelTCPConnectionStateCancelled;
        default: return RVPNTunnelTCPConnectionStateInvalid;
    }
}

- (void)write:(NSData *)data completionHandler:(void (^)(NSError * _Nullable))completionHandler {
    [self.connection write:data completionHandler:completionHandler];
}

- (void)readMinimumLength:(NSUInteger)minimumLength
           maximumLength:(NSUInteger)maximumLength
       completionHandler:(void (^)(NSData * _Nullable, NSError * _Nullable))completionHandler {
    [self.connection readMinimumLength:minimumLength maximumLength:maximumLength completionHandler:completionHandler];
}

- (void)cancel { [self.connection cancel]; }
- (void)dealloc { [_connection cancel]; }
@end
