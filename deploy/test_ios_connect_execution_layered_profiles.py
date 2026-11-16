#!/usr/bin/env python3
"""Replay independent CONNECT layers through actual profile CRUD callbacks.

Both required phases keep the common driver's original 30-second runtime
bound. The unchanged full-count profile gate remains mandatory separately.
"""
import test_ios_node_chain_connect_profiles as C

PROFILE_NODE_COUNTS = (4, 8)
TYPED = C.TYPED


def replace(before, after):
    global TYPED
    assert TYPED.count(before) == 1, before
    TYPED = TYPED.replace(before, after, 1)


replace('static func setupTyped(_ count:Int=3)', 'static func setupTyped(_ count:Int=3,_ entryLayer:String="off")')
replace('LibboxTestAWGFixture(count,"off")', 'LibboxTestAWGFixture(count,entryLayer)')
replace('''  for count in 3...8 {for mode in (count==3 ? ["wg","awg2-fast","awg2-strong"]:["wg"]) {for host in (count==3 ? ["198.51.100.76","2001:db8::76"]:["198.51.100.76"]) {for authenticated in (count==3 ? [false,true]:[true]) {for kind in ["http-connect","https-connect"] {for requested in ([3,4,8].contains(count) && mode=="wg" && host=="198.51.100.76" && authenticated ? ["local","server","auto"]:["local"]) {''', '''  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),[4,8].contains(count) else {throw failure("missing captured CONNECT layer profile phase")}
  var completedCases=0
  for kind in ["http-connect","https-connect"] {for requested in ["server","auto"] {for finalLayer in ["aes-256-gcm","aes-256-gcm+xor-whitening"] {
   let mode="awg2-strong",host="198.51.100.76",authenticated=true
   let entryLayer=count==8 ? "off":finalLayer=="aes-256-gcm" ? "aes-256-gcm+xor-whitening":"aes-256-gcm"''')
replace('setupTyped(count),store=', 'setupTyped(count,entryLayer),store=')
replace('var final=model.bundle!;final.routerProfiles[0].multihopExecution=requested;', 'var final=model.bundle!;final.routerProfiles[0].startLayer=finalLayer;final.routerProfiles[0].multihopExecution=requested;')
replace('   try check("typed profile retains external authority",', '   try check("layered CONNECT profile stores independent original layers",saved.preferences?.startLayer==finalLayer && saved.chainPolicies?.first?.preferences.startLayer==entryLayer && saved.chainPolicies?.last?.preferences.startLayer==finalLayer)\n   try check("typed profile retains external authority",')
replace('   try check("typed profile Load keeps paired final assets",model.bundle!.profiles==originalAssets)', '   try check("typed profile Load keeps paired final assets",model.bundle!.profiles==originalAssets)\n   try check("layered CONNECT Load retains independent original layers",captured.first?.routerProfiles.first?.startLayer==entryLayer && captured.last?.routerProfiles.first?.startLayer==finalLayer)')
replace('  }}}}}}\n }\n', '   completedCases+=1\n  }}}\n  try check("complete CONNECT layered profile phase",completedCases==8)\n }\n')


def main():
    C.TYPED = TYPED
    C.main(label="layered CONNECT", roundtrip="connectRoundtrip", binary_cases=[(count,) for count in PROFILE_NODE_COUNTS])


if __name__ == '__main__':
    main()
