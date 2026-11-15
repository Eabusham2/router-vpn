#!/usr/bin/env python3
"""Required paired-node child/Box boundaries on the original native race images.

These are component ownership controls. The separate installed app gate owns
actual paired traffic and public Connect acceptance.
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import re

ROOT = Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('paired_node_platform',ROOT/'deploy/test_darwin_paired_node_platform.py')
PLATFORM=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(PLATFORM)
_spec=importlib.util.spec_from_file_location('paired_mtu_reader',ROOT/'deploy/test_darwin_paired_mtu_reader.py')
READER=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(READER)
ROOTS = {'TestRouterVPNNodeDarwinOriginalControl': ('exact',
                                            'policy-pointer',
                                            'replacement-root',
                                            'late-source',
                                            'missing-authority',
                                            'capture',
                                            'handshake',
                                            'retiring'),
 'TestRouterVPNNodeDarwinSelectionBinding': ('session',
                                             'source',
                                             'config',
                                             'uid',
                                             'device',
                                             'inode',
                                             'engine',
                                             'controller',
                                             'catalog',
                                             'inputs',
                                             'family'),
 'TestRouterVPNNodeDarwinEarlyStop': ('receipt-before-acquisition', 'authenticated-before-run'),
 'TestRouterVPNNodeDarwinDNSStartup': ('absent',
                                       'request-regular',
                                       'request-directory',
                                       'request-symlink',
                                       'cancel-regular',
                                       'cancel-directory',
                                       'cancel-symlink',
                                       'result-regular',
                                       'result-directory',
                                       'result-symlink'),
 'TestRouterVPNNodeDarwinStoppedReceipt': ('joined',
                                           'source-retry',
                                           'box-failure',
                                           'foreign-file',
                                           'foreign-workspace',
                                           'authenticated-ack'),
 'TestRouterVPNNodeDarwinManifestReplay': ('missing-source',
                                           'missing-policy',
                                           'missing-config',
                                           'changed-source',
                                           'changed-policy',
                                           'changed-config',
                                           'duplicate-policy',
                                           'foreign-field',
                                           'null-mtu',
                                           'missing-mtu',
                                           'session',
                                           'source',
                                           'config'),
 'TestRouterVPNNodeDarwinCommandFlags': ('imported-source-sha256',
                                         'physical-transfer-sha256',
                                         'physical-mtu',
                                         'journal-parent-handle',
                                         'journal-parent-image',
                                         'journal-pipe',
                                         'journal-capture-sha256',
                                         'linux-parent-channel',
                                         'linux-parent-directory',
                                         'linux-parent-capture',
                                         'exact-captured-arguments',
                                         'empty-family',
                                         'unknown-family'),
 'TestRouterVPNNodeMTUPairedDarwinAdoptsOnlyConfirmedSuccessors': (),
 'TestRouterVPNNodeMTUPairedDarwinRefusesUnownedRename': ('no-capability', 'refused-capability', 'same-index', 'retired-during-confirmation', 'mixed-prefix', 'mixed-openvpn'),
 'TestRouterVPNNodeMTUPairedDarwinCancelledChangeRetainsOnlyOriginalRollback': (),
 'TestRouterVPNDesktopNodeDarwinOriginalPhysical': ('exact',
                                                    'foreign-policy',
                                                    'descriptor-refusal',
                                                    'retirement-retry'),
 'TestRouterVPNDesktopNodeDarwinRejectsForeignControl': (),
 'TestRouterVPNDesktopNodeDarwinPairedMTUReader': ('original', 'nil-context', 'cancelled', 'foreign-box', 'foreign-reader', 'nil-policy', 'wrapped-policy', 'linux-policy', 'session', 'config', 'fixed-alias', 'detached', 'wrong-name', 'non-ascii-name', 'index', 'index-overflow', 'mtu', 'changed-readback', 'retired-source')}

CASES = tuple(name for root, leaves in ROOTS.items() for name in (root, *(root+'/'+leaf for leaf in leaves)))
PHASES = tuple((role, '^('+'|'.join(root for root in ROOTS if root.startswith(prefix))+')$',
                tuple(name for name in CASES if name.startswith(prefix)))
               for role,prefix in (('command',('TestRouterVPNNodeDarwin','TestRouterVPNNodeMTUPairedDarwin')),('box','TestRouterVPNDesktopNodeDarwin')))


def checked_phases():
    expected = tuple((role, '^('+'|'.join(root for root in ROOTS if root.startswith(prefix))+')$',
                      tuple(name for name in CASES if name.startswith(prefix)))
                     for role,prefix in (('command',('TestRouterVPNNodeDarwin','TestRouterVPNNodeMTUPairedDarwin')),('box','TestRouterVPNDesktopNodeDarwin')))
    if PHASES != expected or len(CASES)!=105 or len(set(CASES))!=105 or tuple(len(row[2]) for row in PHASES)!=(79,26):
        raise ValueError('paired-node required native inventory changed')
    if tuple(name for row in PHASES for name in row[2]) != CASES:
        raise ValueError('paired-node native phases omitted or repeated an original verdict')
    return PHASES


def source_digest(source):
    return hashlib.sha256(json.dumps(source,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def validate_receipt(receipt, sources, child_hash, box_hash=None):
    expected={'schema','scope','verdicts','cases','phases','source_sha256','command_sha256','box_sha256','output_sha256'}
    if (not isinstance(receipt,dict) or set(receipt)!=expected or receipt['schema']!=1
            or receipt['scope']!='paired-node-component-boundaries' or receipt['verdicts']!=105
            or receipt['cases']!=list(CASES) or receipt['phases']!=['command','box']
            or receipt['source_sha256']!=sources or receipt['command_sha256']!=child_hash
            or box_hash is not None and receipt['box_sha256']!=box_hash
            or any(not isinstance(receipt[key],str) or re.fullmatch('[0-9a-f]{64}',receipt[key]) is None
                   for key in ('box_sha256','output_sha256','command_sha256','source_sha256'))):
        raise ValueError('paired-node native boundary receipt is incomplete or belongs to another image/source')
    checked_phases()


def execute(gate, source, before, compiler, captured, child, identities, work):
    phases=checked_phases()
    PLATFORM.verify(go=str(compiler))
    READER.execute(go=str(compiler))
    box=work/'paired-node-box.test'
    gate.UID.run(gate.native_fixture_compile(compiler,box,'.'),cwd=source,env=captured,timeout=600)
    gate.UID.RACE.verify_image(compiler,box,source,captured)
    box.chmod(0o755)
    original=dict(identities)
    original[box]=gate.image_identity(box)
    outputs=[]
    for role,selector,verdicts in phases:
        if gate.checked_sources(source)[1]!=before or any(gate.image_identity(path)!=value for path,value in original.items()):
            raise ValueError('paired-node native source or image changed before phase')
        image=child if role=='command' else box
        output=gate.UID.run([image,'-test.run='+selector,'-test.v','-test.count=1','-test.timeout=90s'],
                            cwd=source,env=captured,timeout=100)
        gate.NODE.require_native_verdicts(output,verdicts,'original paired-node '+role+' boundaries')
        if gate.checked_sources(source)[1]!=before or any(gate.image_identity(path)!=value for path,value in original.items()):
            raise ValueError('paired-node native source or image changed during phase')
        outputs.append(output)
        print(output,end='' if output.endswith('\n') else '\n',flush=True)
    receipt=dict(schema=1,scope='paired-node-component-boundaries',verdicts=105,cases=list(CASES),
                 phases=[row[0] for row in phases],source_sha256=source_digest(before),
                 command_sha256=original[child][-1],box_sha256=original[box][-1],
                 output_sha256=hashlib.sha256(''.join(outputs).encode()).hexdigest())
    validate_receipt(receipt,source_digest(before),original[child][-1])
    identities[box]=original[box]
    return receipt
