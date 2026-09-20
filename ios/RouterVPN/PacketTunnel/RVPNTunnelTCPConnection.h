#import <Foundation/Foundation.h>
#import <NetworkExtension/NEPacketTunnelProvider.h>

NS_ASSUME_NONNULL_BEGIN

// The iOS 17 in-provider API is still public Objective-C API, but is hidden
// by the SDK's Swift 6 overlay. Keep it behind this narrow typed adapter rather
// than weakening Swift mode or falling back to an unbound ordinary connection.
typedef NS_ENUM(NSInteger, RVPNTunnelTCPConnectionState) {
    RVPNTunnelTCPConnectionStateInvalid,
    RVPNTunnelTCPConnectionStateConnecting,
    RVPNTunnelTCPConnectionStateWaiting,
    RVPNTunnelTCPConnectionStateConnected,
    RVPNTunnelTCPConnectionStateDisconnected,
    RVPNTunnelTCPConnectionStateCancelled,
};

@interface RVPNTunnelTCPConnection : NSObject
@property (nonatomic, readonly) RVPNTunnelTCPConnectionState state;
- (nullable instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                                    host:(NSString *)host
                                    port:(uint16_t)port
    NS_DESIGNATED_INITIALIZER NS_SWIFT_NAME(init(provider:host:port:));
- (instancetype)init NS_UNAVAILABLE;
- (void)write:(NSData *)data completionHandler:(void (^)(NSError * _Nullable error))completionHandler;
- (void)readMinimumLength:(NSUInteger)minimumLength
           maximumLength:(NSUInteger)maximumLength
       completionHandler:(void (^)(NSData * _Nullable data, NSError * _Nullable error))completionHandler;
- (void)cancel;
@end

NS_ASSUME_NONNULL_END
