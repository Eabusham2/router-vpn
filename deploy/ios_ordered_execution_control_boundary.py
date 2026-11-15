"""Explicitly rejecting ordered-execution boundary for unrelated legacy host tests.

Typed CONNECT tests compile the actual control/source and real shared compiler.
This boundary never constructs or accepts a live ordered execution owner.
"""
SWIFT=r'''
enum IOSNodeChainExecutionSession {
 struct Source:Equatable {let requested:String="";static func capture(_ identity:IOSSessionIdentity)throws->Source{throw CancellationError()}}
 struct Restoration {let execution:String=""}
 struct Last {}
 static func issue()->NSError{NSError(domain:"UnrelatedOrderedExecutionBoundary",code:1)}
}
@MainActor final class IOSNodeChainExecutionControl {
 struct Observation{let last:IOSNodeChainExecutionSession.Last}
 static func observe(source:IOSNodeChainExecutionSession.Source,send:@MainActor(Data)async throws->Data,current:@MainActor()throws->Void)async throws->Observation{throw CancellationError()}
 static func startupLast(input:String,finalProfile:Any)throws->[String:NSObject]{throw CancellationError()}
 let source:IOSNodeChainExecutionSession.Source
 let restoration:IOSNodeChainExecutionSession.Restoration?=nil
 init(source:IOSNodeChainExecutionSession.Source,owner:UUID,send:@escaping @MainActor(Data)async throws->Data,current:@escaping @MainActor()throws->Void){self.source=source}
 static func requireAvailable()async throws{}
 func capture()async throws{throw CancellationError()}
 func verify()async throws{throw CancellationError()}
 func options()throws->[String:NSObject]{throw CancellationError()}
 func proveRestored(send:@MainActor(Data)async throws->Data,current:@MainActor()throws->Void)async throws{throw CancellationError()}
 func retire()async throws{throw CancellationError()}
}
@MainActor enum IOSNodeChainExecutionLastStore {static func record(_ last:IOSNodeChainExecutionSession.Last)throws{throw CancellationError()}}
'''

REFRESH=r'''
@MainActor enum IOSSpeedLabTunnel {static func sendOrdered(_ connection:NETunnelProviderSession,data:Data)async throws->Data{throw CancellationError()}}
'''
