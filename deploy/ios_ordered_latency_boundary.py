"""Explicit native facade double for shipping Swift host/IPC compilation; not ABI/native acceptance."""
NATIVE=r'''
public final class LibboxRouterOrderedLatency {
 public init(){}
 public func start(_ request:String,nodeID:String)throws{}
 public func cancel(_ request:String){}
 public func drain(_ request:String)throws{}
 public func statusJSON()->String{"{}"}
 public func savedJSON(_ node:String)->String{""}
 public func close()throws{}
}
public func LibboxRouterNodeChainSOCKSNewLatencyBenchmark(_ plan:LibboxRouterNodeChainSOCKS,_ server:LibboxCommandServer,_ measurement:LibboxRouterHopMeasurement,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterOrderedLatency?{
 guard plan.healthy() else{error?.pointee=NSError(domain:"OrderedLatencyBoundary",code:1);return nil};return LibboxRouterOrderedLatency()
}
public func LibboxRouterValidatePrivateNodeJSON(_ raw:String,_ failure:UnsafeMutablePointer<NSError?>?)->Bool{
 do{_ = try JSONSerialization.jsonObject(with:Data(raw.utf8));return true}catch{return false}
}
'''

CONNECT_FACTORY=r'''
public func LibboxRouterNodeChainCONNECTNewLatencyBenchmark(_ plan:LibboxRouterNodeChainCONNECT,_ server:LibboxCommandServer,_ measurement:LibboxRouterHopMeasurement,_ error:UnsafeMutablePointer<NSError?>?)->LibboxRouterOrderedLatency?{
 guard plan.healthy() else{error?.pointee=NSError(domain:"OrderedLatencyBoundary",code:1);return nil};return LibboxRouterOrderedLatency()
}
'''
