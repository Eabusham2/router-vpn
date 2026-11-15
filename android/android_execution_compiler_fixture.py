"""Shared actual Go execution compiler boundary for Android source fixtures.

Construction and Last parsing invoke shipping mobilemultihop constructors.
Native Run/proof/MTU/restore remain explicitly refusing boundaries.
"""

def compiler_source(source):
    cases = r'''case len(args)==3&&args[0]=="socks-execution-preparation":result,err=socksExecutionPreparation(args[1],args[2]);case len(args)==2&&args[0]=="socks-execution-replay":result,err=socksExecutionReplay(args[1]);case len(args)==4&&args[0]=="socks-execution-last":result,err=socksExecutionLast(args[1],args[2],args[3]);case len(args)==3&&args[0]=="connect-execution-preparation":result,err=connectExecutionPreparation(args[1],args[2]);case len(args)==2&&args[0]=="connect-execution-replay":result,err=connectExecutionReplay(args[1]);case len(args)==4&&args[0]=="connect-execution-last":result,err=connectExecutionLast(args[1],args[2],args[3]);case len(args)==3&&args[0]=="execution-preparation":result,err=executionPreparation(args[1],args[2]);case len(args)==2&&args[0]=="execution-replay":result,err=executionReplay(args[1]);case len(args)==4&&args[0]=="execution-last":result,err=executionLast(args[1],args[2],args[3]);'''
    assert source.count("case len(args)==2:") == 1
    return source.replace("case len(args)==2:", cases + "case len(args)==2:") + r'''
func socksExecutionPreparation(input,requested string)(string,error){
 original,err:=mobilemultihop.NewNodeChainSOCKSSource(input);if err!=nil{return "",err};prep,err:=mobilemultihop.NewNodeChainSOCKSExecutionPreparation(original,requested);if err!=nil{return "",err};return executionPrepared(prep)
}
func socksExecutionReplay(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var envelope executionEnvelope;var fields map[string]json.RawMessage
 if err:=json.Unmarshal([]byte(input),&fields);err!=nil{return "",err};if len(fields)!=5{return "",fmt.Errorf("unexpected typed envelope")}
 if err:=json.Unmarshal([]byte(input),&envelope);err!=nil{return "",err};if envelope.Kind!="routervpn-node-chain-socks-execution-preparation-input"||envelope.Schema!=1{return "",fmt.Errorf("foreign typed envelope")}
 prep,err:=mobilemultihop.ParseNodeChainSOCKSExecutionPreparation(envelope.Source);if err!=nil{return "",err}
 if prep.SourceSHA256()!=envelope.SourceSHA||prep.ConfigSHA256()!=envelope.ConfigSHA{return "",fmt.Errorf("changed typed source")};return executionPrepared(prep)
}
func socksExecutionLast(input,requested,lastJSON string)(string,error){
 raw,err:=socksExecutionPreparation(input,requested);if err!=nil{return "",err};var values map[string]string;if err=json.Unmarshal([]byte(raw),&values);err!=nil{return "",err}
 prep,err:=mobilemultihop.ParseNodeChainSOCKSExecutionPreparation(values["source"]);if err!=nil{return "",err};last,err:=mobilemultihop.ParseNodeChainExecutionLast(lastJSON,prep);if err!=nil{return "",err}
 var envelope map[string]any;if err=json.Unmarshal([]byte(values["launch"]),&envelope);err!=nil{return "",err};envelope["schema"]=2;envelope["last"]=last.JSON();launch,err:=json.Marshal(envelope);if err!=nil{return "",err};values["launch"]=string(launch);result,err:=json.Marshal(values);return string(result),err
}
func connectExecutionPreparation(input,requested string)(string,error){
 original,err:=mobilemultihop.NewNodeChainCONNECTSource(input);if err!=nil{return "",err};prep,err:=mobilemultihop.NewNodeChainCONNECTExecutionPreparation(original,requested);if err!=nil{return "",err};return executionPrepared(prep)
}
func connectExecutionReplay(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var envelope executionEnvelope;var fields map[string]json.RawMessage
 if err:=json.Unmarshal([]byte(input),&fields);err!=nil{return "",err};if len(fields)!=5{return "",fmt.Errorf("unexpected typed envelope")}
 if err:=json.Unmarshal([]byte(input),&envelope);err!=nil{return "",err};if envelope.Kind!="routervpn-node-chain-connect-execution-preparation-input"||envelope.Schema!=1{return "",fmt.Errorf("foreign typed envelope")}
 prep,err:=mobilemultihop.ParseNodeChainCONNECTExecutionPreparation(envelope.Source);if err!=nil{return "",err}
 if prep.SourceSHA256()!=envelope.SourceSHA||prep.ConfigSHA256()!=envelope.ConfigSHA{return "",fmt.Errorf("changed typed source")};return executionPrepared(prep)
}
func connectExecutionLast(input,requested,lastJSON string)(string,error){
 raw,err:=connectExecutionPreparation(input,requested);if err!=nil{return "",err};var values map[string]string;if err=json.Unmarshal([]byte(raw),&values);err!=nil{return "",err}
 prep,err:=mobilemultihop.ParseNodeChainCONNECTExecutionPreparation(values["source"]);if err!=nil{return "",err};last,err:=mobilemultihop.ParseNodeChainExecutionLast(lastJSON,prep);if err!=nil{return "",err}
 var envelope map[string]any;if err=json.Unmarshal([]byte(values["launch"]),&envelope);err!=nil{return "",err};envelope["schema"]=2;envelope["last"]=last.JSON();launch,err:=json.Marshal(envelope);if err!=nil{return "",err};values["launch"]=string(launch);result,err:=json.Marshal(values);return string(result),err
}
type executionEnvelope struct{Kind string `json:"kind"`;Schema int `json:"schema"`;Source string `json:"source"`;SourceSHA string `json:"source_sha256"`;ConfigSHA string `json:"config_sha256"`}
func executionPrepared(prep *mobilemultihop.NodeChainExecutionPreparation)(string,error){
 kind:="routervpn-node-chain-execution-preparation-input";if prep.RequiresSOCKSExecutionObserver(){kind="routervpn-node-chain-socks-execution-preparation-input"};if prep.RequiresCONNECTExecutionObserver(){kind="routervpn-node-chain-connect-execution-preparation-input"};launch,err:=json.Marshal(executionEnvelope{kind,1,prep.Source(),prep.SourceSHA256(),prep.ConfigSHA256()});if err!=nil{return "",err}
 raw,err:=json.Marshal(map[string]string{"source":prep.Source(),"source_sha256":prep.SourceSHA256(),"config":prep.Config(),"config_sha256":prep.ConfigSHA256(),"local_source_sha256":prep.LocalSourceSHA256(),"requested":prep.Execution(),"launch":string(launch)});return string(raw),err
}
func executionPreparation(input,requested string)(string,error){
 if _,err:=mobilemultihop.ParseNodeChainLaunchInput(input);err!=nil{return "",err}
 var original mobilemultihop.NodeChainSource;if err:=json.Unmarshal([]byte(input),&original);err!=nil{return "",err};raw,err:=json.Marshal(original);if err!=nil{return "",err}
 prep,err:=mobilemultihop.NewNodeChainExecutionPreparation(string(raw),requested);if err!=nil{return "",err};return executionPrepared(prep)
}
func executionReplay(input string)(string,error){
 if err:=libbox.RouterValidatePrivateNodeJSON(input);err!=nil{return "",err}
 var envelope executionEnvelope;var fields map[string]json.RawMessage
 if err:=json.Unmarshal([]byte(input),&fields);err!=nil{return "",err};if len(fields)!=5{return "",fmt.Errorf("unexpected execution envelope")}
 if err:=json.Unmarshal([]byte(input),&envelope);err!=nil{return "",err};if envelope.Kind!="routervpn-node-chain-execution-preparation-input"||envelope.Schema!=1{return "",fmt.Errorf("foreign execution envelope")}
 if err:=libbox.RouterValidatePrivateNodeJSON(envelope.Source);err!=nil{return "",err}
 var source mobilemultihop.NodeChainExecutionPreparationSource
 if err:=json.Unmarshal([]byte(envelope.Source),&source);err!=nil{return "",err}
 prep,err:=mobilemultihop.NewNodeChainExecutionPreparation(source.LocalSource,source.Execution);if err!=nil{return "",err}
 if source.Schema!=1||prep.Source()!=envelope.Source||prep.SourceSHA256()!=envelope.SourceSHA||prep.ConfigSHA256()!=envelope.ConfigSHA{return "",fmt.Errorf("changed execution source")}
 return executionPrepared(prep)
}
func executionLast(input,requested,lastJSON string)(string,error){
 raw,err:=executionPreparation(input,requested);if err!=nil{return "",err}
 var values map[string]string;if err=json.Unmarshal([]byte(raw),&values);err!=nil{return "",err}
 var source mobilemultihop.NodeChainExecutionPreparationSource;if err=json.Unmarshal([]byte(values["source"]),&source);err!=nil{return "",err}
 prep,err:=mobilemultihop.NewNodeChainExecutionPreparation(source.LocalSource,source.Execution);if err!=nil{return "",err}
 last,err:=mobilemultihop.ParseNodeChainExecutionLast(lastJSON,prep);if err!=nil{return "",err}
 envelope:=struct{Kind string `json:"kind"`;Schema int `json:"schema"`;Source string `json:"source"`;SourceSHA string `json:"source_sha256"`;ConfigSHA string `json:"config_sha256"`;Last string `json:"last"`}{"routervpn-node-chain-execution-preparation-input",2,prep.Source(),prep.SourceSHA256(),prep.ConfigSHA256(),last.JSON()}
 launch,err:=json.Marshal(envelope);if err!=nil{return "",err};values["launch"]=string(launch);result,err:=json.Marshal(values);return string(result),err
}
'''

NATIVE = r'''package io.nekohasekai.libbox;
import org.json.*;
public final class RouterNodeChainExecution {
 public final JSONObject value;public boolean closed;
 RouterNodeChainExecution(String raw)throws Exception{value=new JSONObject(raw);java.util.function.Consumer<RouterNodeChainExecution> hook=Libbox.afterExecution;Libbox.afterExecution=null;if(hook!=null)hook.accept(this);}
 private void current(){if(closed)throw new IllegalStateException("retired pure execution constructor");}
 public String source()throws Exception{current();return value.getString("source");}public String launchInput()throws Exception{current();return value.getString("launch");}
 public String config()throws Exception{current();return value.getString("config");}public String sourceSHA256()throws Exception{current();return value.getString("source_sha256");}
 public String configSHA256()throws Exception{current();return value.getString("config_sha256");}public String localSourceSHA256()throws Exception{current();return value.getString("local_source_sha256");}
 public String requestedExecution()throws Exception{current();return value.getString("requested");}
 public void bindNative(CommandServer server){throw new AssertionError("Source-only gate cannot bind a native execution");}public boolean nativeClosed(){return false;}
 public void run(CommandServer server){throw new AssertionError("Source-only gate cannot run a native execution");}public boolean healthy(){return false;}
 public String execution(){throw new IllegalStateException("No native execution proof");}public String progressJSON(){return "{}";}
 public void networkChanged(){}public boolean retainsServerCleanup(CommandServer server){return false;}public void close(){closed=true;}
 public String captureLastJSON(){throw new IllegalStateException("No native Last proof in source-only fixture");}
 public RouterNodeChainExecutionRestoreCapture captureRestore(){throw new IllegalStateException("No native restore owner");}
 public void requireRestore(RouterNodeChainExecutionRestoreCapture capture){throw new IllegalStateException("No native restore authority in pure source fixture");}
}
'''

def prepare_native(src):
    native = src / "io/nekohasekai/libbox"
    (native / "RouterNodeChainExecution.java").write_text(NATIVE)
    for name in ("CommandServer", "RouterNodeChainExecutionRestoreCapture", "RouterMTU", "RouterHopMeasurement"):
        (native / (name + ".java")).write_text("package io.nekohasekai.libbox;public final class " + name + "{}")
    (native / "RouterMTUPlatform.java").write_text("package io.nekohasekai.libbox;public interface RouterMTUPlatform{}")
    path = native / "Libbox.java"
    source = path.read_text()
    marker = "static String call(String...args)throws Exception{"
    assert source.count(marker) == 1
    methods = r'''public static java.util.function.Consumer<RouterNodeChainExecution> afterExecution;
public static RouterNodeChainExecution newRouterNodeChainSOCKSExecution(String source,String requested)throws Exception{return new RouterNodeChainExecution(call("socks-execution-preparation",source,requested));}
public static RouterNodeChainExecution newRouterNodeChainSOCKSExecutionLaunch(String source)throws Exception{return new RouterNodeChainExecution(call("socks-execution-replay",source));}
public static RouterNodeChainExecution routerNodeChainSOCKSExecutionFromLast(String source,String requested,String last)throws Exception{return new RouterNodeChainExecution(call("socks-execution-last",source,requested,last));}
public static RouterNodeChainExecution newRouterNodeChainCONNECTExecution(String source,String requested)throws Exception{return new RouterNodeChainExecution(call("connect-execution-preparation",source,requested));}
public static RouterNodeChainExecution newRouterNodeChainCONNECTExecutionLaunch(String source)throws Exception{return new RouterNodeChainExecution(call("connect-execution-replay",source));}
public static RouterNodeChainExecution routerNodeChainCONNECTExecutionFromLast(String source,String requested,String last)throws Exception{return new RouterNodeChainExecution(call("connect-execution-last",source,requested,last));}

public static RouterNodeChainExecution routerNodeChainExecutionFromLaunch(String source,String requested)throws Exception{return new RouterNodeChainExecution(call("execution-preparation",source,requested));}
public static RouterNodeChainExecution routerNodeChainExecutionFromLast(String source,String requested,String last)throws Exception{return new RouterNodeChainExecution(call("execution-last",source,requested,last));}
public static RouterNodeChainExecution newRouterNodeChainExecutionLaunch(String source)throws Exception{return new RouterNodeChainExecution(call("execution-replay",source));}
public static RouterNodeChainExecution newRouterNodeChainExecutionRestore(RouterNodeChainExecutionRestoreCapture captured){throw new AssertionError("No native restore owner in source-only fixture");}
public static RouterMTU routerNodeChainExecutionNewMTU(RouterNodeChainExecution plan,CommandServer server,RouterMTUPlatform platform){throw new AssertionError("No native MTU in source-only fixture");}
public static RouterHopMeasurement routerNodeChainExecutionNewHopMeasurement(RouterNodeChainExecution plan,CommandServer server){throw new AssertionError("No native measurement in source-only fixture");}
'''
    path.write_text(source.replace(marker, methods + marker))
