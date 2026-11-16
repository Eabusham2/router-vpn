#!/usr/bin/env python3
"""Execute Apple OpenVPN factory, original host and joined measurement ownership.

The shipping Swift bodies run with explicit Libbox, MTU and OS doubles.
Connected OpenVPN endpoint/packet evidence belongs to the native runtime gate.
"""
from pathlib import Path
import ast
import importlib.util
import textwrap

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'original_socks_execution_runtime', ROOT / 'deploy/test_ios_socks_execution_runtime.py')
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

NATIVE = S.C.NATIVE
original = ''' CommandFactory.shared.typed+=1;let server=LibboxCommandServer();CommandFactory.shared.created=server
 if CommandFactory.shared.fail{error?.pointee=failure("factory failed after acquisition")};return server'''
refusal = ' error?.pointee=failure("ordinary CONNECT fixture cannot own an OpenVPN execution");return nil'
assert NATIVE.count(original) == 1 and NATIVE.count(refusal) == 1
NATIVE = NATIVE.replace(original, ' CommandFactory.shared.ordinary+=1;return LibboxCommandServer()', 1)
NATIVE = NATIVE.replace(refusal, original, 1)
TESTS = S.TESTS.replace('isSOCKS', 'isOpenVPN').replace('"socks"', '"openvpn"').replace('SOCKS', 'OpenVPN')


def main():
    prepare = (ROOT / 'ios/RouterVPN/prepare-libbox.sh').read_text()
    block = prepare.split('    # OPENVPN_EXECUTION_ABI_BEGIN\n', 1)[1].split('    # OPENVPN_EXECUTION_ABI_END', 1)[0]
    tree = ast.parse(textwrap.dedent(block))
    assert len(tree.body) == 1 and isinstance(tree.body[0], ast.For)
    signatures = ast.literal_eval(tree.body[0].iter)
    names = ('LibboxRouterNodeChainOpenVPNExecutionFromLaunch(',
             'LibboxNewRouterNodeChainOpenVPNExecutionLaunch(',
             'LibboxRouterNodeChainOpenVPNExecutionFromLast(',
             'LibboxRouterNodeChainOpenVPNExecutionNewCommandServer(')
    assert len(signatures) == 4 and all(sum(name in value for value in signatures) == 1 for name in names)
    content = '\n'.join(signatures)
    check = compile(tree, 'actual-apple-openvpn-abi-check', 'exec')
    exec(check, {'content': content})
    for signature in signatures:
        try:
            exec(check, {'content': content.replace(signature, '')})
        except AssertionError:
            pass
        else:
            raise AssertionError('Missing exact OpenVPN constructor ABI was accepted')
    print('PASS Apple OpenVPN ABI4 and missing-signature4 controls', flush=True)
    S.main(native=NATIVE, tests=TESTS, family='OpenVPN')


if __name__ == '__main__':
    main()
