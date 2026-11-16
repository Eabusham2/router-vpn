#!/usr/bin/env python3
"""Exercise complete SOCKS prefix Last/restore through the actual source bridge.

The existing explicit native-reader/Instance.Close boundary remains separate
from the real shared descriptor and saved-choice parsers. No device traffic or
native join is fabricated by this source/component fixture.
"""
import test_ios_node_chain_execution_restore_last as LAST
import test_ios_socks_execution_capture as SOURCE

PREFIX_NODE_COUNTS = (3, 4, 5, 6, 7, 8)


def main():
    swift = LAST.SWIFT
    begin = swift.index('func socksFixture(')
    end = swift.index('@main struct Tests', begin)
    source_begin = SOURCE.SWIFT.index('func socksFixture(')
    source_end = SOURCE.SWIFT.index('@main struct Tests', source_begin)
    swift = swift[:begin] + SOURCE.SWIFT[source_begin:source_end] + swift[end:]
    begin = swift.index('  var paths=[[Data]]()')
    end = swift.index('  for bundles in paths{', begin)
    swift = swift[:begin] + r'''
  guard CommandLine.arguments.count==3,let count=Int(CommandLine.arguments[2]),(3...8).contains(count) else {fatalError("missing captured SOCKS Last phase")}
  var paths=[[Data]]()
  for mode in ["wg","awg2-fast","awg2-strong"]{for authenticated in [false,true]{paths.append(try socksFixture(mode,"auto",authenticated,count))}}
''' + swift[end:]
    before = 'socksFixture(mode,"server",true)'
    assert swift.count(before) == 1
    swift = swift.replace(before, 'socksFixture(mode,"server",true,count)', 1)
    before = '  print("PASS Apple typed restore/Last: \\(checks) checks")'
    assert swift.count(before) == 1
    swift = swift.replace(before, '  print("PASS Apple SOCKS prefix restore/Last nodes=\\(count): \\(checks) checks")', 1)
    LAST.SWIFT = swift
    LAST.main(binary_cases=[(count,) for count in PREFIX_NODE_COUNTS])


if __name__ == '__main__':
    main()
