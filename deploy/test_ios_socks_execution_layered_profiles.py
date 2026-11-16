#!/usr/bin/env python3
"""Replay layered SOCKS profiles through actual callbacks and full execution source.

The published six complete-count profile phases remain required separately.
This additive gate uses eight selected-layer combinations and the original
private-source race and persistence controls, with explicit store/OS doubles.
"""
import test_ios_node_chain_connect_profiles as C
import test_ios_node_chain_socks_profiles as S

TYPED=S.TYPED


def replace(before, after):
    global TYPED
    assert TYPED.count(before)==1, before
    TYPED=TYPED.replace(before,after,1)


replace('static func setupTyped(_ count:Int=3)', 'static func setupTyped(_ count:Int=3,_ entryLayer:String="off")')
replace('LibboxTestAWGFixture(count,"off")', 'LibboxTestAWGFixture(count,entryLayer)')
replace(''' static func socksProfileSource(_ bundles:[Data],_ execution:String)throws->IOSNodeChainSOCKSCapture {
  if execution=="local" {return try IOSNodeChainSOCKSCapture.compile(bundles:bundles)}
  return try IOSNodeChainSOCKSCapture.compileOriginalForExecution(bundles:bundles,requested:execution)
 }''', ''' static func socksProfileSource(_ bundles:[Data],_ execution:String)throws->IOSNodeChainExecutionCapture {
  try IOSNodeChainExecutionCapture.compile(bundles:bundles,requested:execution)
 }''')
replace('''  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(3...8).contains(count) else {throw failure("missing captured SOCKS profile phase")}
  for execution in ["local","server","auto"] {for mode in ["wg","awg2-fast","awg2-strong"] {for host in ["198.51.100.76","2001:db8::76"] {for authenticated in [false,true] {''', '''  for count in [4,8] {for execution in ["server","auto"] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {
   // The saved packet budget is unchanged. Independent wrapped prefixes fit
   // the four-node fixture; the complete eight-node fixture retains Off there.
   let mode="awg2-strong",host="198.51.100.76",authenticated=true
   let entryLayer=count==8 ? "off":finalLayer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm"''')
replace('setupTyped(count),store=', 'setupTyped(count,entryLayer),store=')
replace('final.routerProfiles[0].multihopExecution=execution;try store.save(final)', 'final.routerProfiles[0].multihopExecution=execution;final.routerProfiles[0].startLayer=finalLayer;try store.save(final)')
replace('beforeSource.plan.close()', 'beforeSource.close()')
replace('afterSource.plan.close()', 'afterSource.close()')
replace('afterSource.selectionExecution==execution', 'afterSource.requested==execution')
replace('   try check("typed profile retains external authority",', '   try check("layered SOCKS profile stores independent original layers",saved.preferences?.startLayer==finalLayer && saved.chainPolicies?.first?.preferences.startLayer==entryLayer && saved.chainPolicies?.last?.preferences.startLayer==finalLayer)\n   try check("typed profile retains external authority",')
replace('   try check("typed profile Load keeps paired final assets",model.bundle!.profiles==originalAssets)', '   try check("typed profile Load keeps paired final assets",model.bundle!.profiles==originalAssets)\n   try check("layered SOCKS Load retains independent original layers",captured.first?.routerProfiles.first?.startLayer==entryLayer && captured.last?.routerProfiles.first?.startLayer==finalLayer)')
replace('  }}}}\n }\n', '  }}}\n }\n')


def main():
    C.TYPED=TYPED
    # The common driver retains the real source compiler, callbacks, full
    # private-source precommit checks, and all three original compiled controls.
    C.main(label="layered SOCKS",roundtrip="socksRoundtrip")


if __name__=='__main__':main()
