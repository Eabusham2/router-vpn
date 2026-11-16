"""Explicitly unavailable typed candidate ABI for unrelated Java fixtures.

These definitions keep existing ordinary/prefix fixtures honest: they may
compile the shipping adapter, but cannot acquire a fabricated typed runtime.
The connected typed host gate replaces them with its labelled native boundary.
"""

NATIVE = 'io/nekohasekai/libbox/'


def unavailable_sources(sources):
    sources = dict(sources)
    sources.setdefault(NATIVE+'RouterNodeChainCandidateCatalog.java', 'package io.nekohasekai.libbox;public interface RouterNodeChainCandidateCatalog{String currentInventorySHA256();}')
    methods = []
    for family in ('SOCKS', 'CONNECT'):
        name = 'RouterNodeChain'+family+'CandidateMeasurement'
        sources[NATIVE+name+'.java'] = '''package io.nekohasekai.libbox;
public final class %s {
 private static IllegalStateException unavailable(){return new IllegalStateException("No typed connected candidate runtime in this ordinary fixture");}
 public String metadata(){throw unavailable();}
 public String captureSHA256(){throw unavailable();}
 public void prepare()throws Exception{throw unavailable();}
 public void start(String request,String id)throws Exception{throw unavailable();}
 public void cancel(String request){throw unavailable();}
 public void drain(String request)throws Exception{throw unavailable();}
 public String statusJSON(){throw unavailable();}
 public void networkChanged(){throw unavailable();}
 public void close()throws Exception{throw unavailable();}
}''' % name
        methods.append('''public static %s routerNodeChain%sNewCandidateMeasurement(RouterNodeChain%s owner,CommandServer server,int prefix,String inventory,Object catalog)throws Exception{throw new IllegalStateException("No typed connected candidate runtime in this ordinary fixture");}''' % (name, family, family))
    path = NATIVE+'Libbox.java'
    original = sources[path]
    if not original.endswith('}'):
        raise ValueError('Ordinary native fixture no longer has its exact class boundary')
    sources[path] = original[:-1]+'\n'+'\n'.join(methods)+'\n}'
    return sources


def install_unavailable(src):
    path = NATIVE+'Libbox.java'
    original = {path: (src/path).read_text()}
    for name, body in unavailable_sources(original).items():
        (src/name).write_text(body)
