"""Additional exact encrypted connected-candidate partitions, never old-case filters."""
from pathlib import Path

CASES={'SOCKS':('3','4','8'), 'CONNECT':tuple(f'{protocol}/{count}' for protocol in ('http-connect','https-connect') for count in (3,4,8))}
TEMPLATE='typed_candidates_run_test.go.tmpl'
PROJECTION='experimental/libbox/routervpn_node_chain_typed_candidates_run_test.go'


def names(family,case):
    if family not in CASES or case not in CASES[family]:raise ValueError('foreign connected candidate partition')
    root='TestRouterNodeChain'+family+'ConnectedCandidateEncrypted'
    return (root,root+'/'+case.replace('/','-'))


def projection(source,core,table):
    original=Path(source)/'mobile/chain'/TEMPLATE;native=Path(core)/PROJECTION
    if table.get(TEMPLATE)!=PROJECTION or original.is_symlink() or native.is_symlink() or original.read_bytes()!=native.read_bytes():
        raise ValueError('changed original encrypted connected candidate projection')


def validate(base,run,compiler,core,peer,client,environment,family):
    if family not in CASES:raise ValueError('foreign connected native family')
    identities=(base.COMMON.image_identity(peer),base.COMMON.image_identity(client))
    records=[]
    for case in CASES[family]:
        expected=names(family,case)
        env={key:value for key,value in environment.items() if not key.startswith('ROUTERVPN_'+family+'_')}
        env.update({'ROUTERVPN_'+family+'_RUN_PEER':str(peer),'ROUTERVPN_'+family+'_CONNECTED_CANDIDATE':case,'GODEBUG':'x509usefallbackroots=1'})
        status,raw=run('connected-candidate-'+case.replace('/','-'),[compiler,'tool','test2json','-t','-p',base.LIBBOX,client,'-test.run=^'+expected[0]+'$','-test.count=1','-test.timeout=180s','-test.v'],core,190,env)
        records.append(dict(case=case,**base.require_events(raw,status,base.LIBBOX,expected)))
        if (base.COMMON.image_identity(peer),base.COMMON.image_identity(client))!=identities:
            raise ValueError('original connected candidate executable changed')
    if [row['case'] for row in records]!=list(CASES[family]):raise ValueError('connected native partition union changed')
    return {'connected_candidate_cases':list(CASES[family]),'connected_candidate_records':records,'connected_candidate_tcp_fifty_accepted':True,'connected_candidate_replacement_authentication_accepted':False,'connected_candidate_installed_host_accepted':False}


def workflow_contract(source,release):
    import re
    required=("  workflow_call:","  encrypted:","    runs-on: ubuntu-24.04","    timeout-minutes: 75","      fail-fast: false","        family: [SOCKS, CONNECT]","  cancel-in-progress: false",
              "          python3 deploy/test_node_chain_typed_connected_candidates_runner.py","          python3 deploy/test_typed_connected_candidates_native_runner.py",
              '          python3 deploy/test_typed_connected_candidates_native.py --source "$GITHUB_WORKSPACE" --require-commit "$GITHUB_SHA" --family \'${{ matrix.family }}\' --output \'${{ runner.temp }}/typed-connected-${{ matrix.family }}\'')
    lines=source.splitlines()
    if any(lines.count(line)!=1 for line in required) or any(line.startswith(('    if:','    continue-on-error:')) for line in lines):
        raise ValueError('required connected encrypted matrix or executor changed')
    if [line for line in lines if line.startswith('    timeout-minutes:')]!=['    timeout-minutes: 75']:
        raise ValueError('connected encrypted budget changed')
    markers=[m.start() for m in re.finditer(r'^  typed-connected-candidates:$',release,re.M)]
    if len(markers)!=1:raise ValueError('connected release dependency missing or duplicated')
    tail=release[markers[0]:];match=re.search(r'\n  \S',tail[3:]);block=tail if match is None else tail[:match.start()+3]
    if block.splitlines().count('    uses: ./.github/workflows/typed-connected-candidates.yml')!=1 or any(line.startswith(('    if:','    with:','    continue-on-error:')) for line in block.splitlines()):
        raise ValueError('connected release source or requirement changed')
    aggregate=release.split('\n  aggregate:\n')
    if len(aggregate)!=2:raise ValueError('connected release aggregate changed')
    needs=[line for line in aggregate[1].splitlines() if line.startswith('    needs:')]
    if len(needs)!=1 or needs[0][len('    needs: ['):-1].split(', ').count('typed-connected-candidates')!=1:
        raise ValueError('connected encrypted acceptance is not mandatory')

ACCOUNTING_ROOT='TestRouterVPNConnectedCandidateTCPAccounting'
ACCOUNTING_LEAVES=('zero','payload','foreign','duplicate','unclosed','read-error','cancelled','close-error','close-only')
ACCOUNTING_TEMPLATE='mobile/desktop/node_wg_peer_test.go.tmpl'
ACCOUNTING_TARGET='protocol/routervpnamnezia/routervpn_desktop_node_wg_peer_test.go'
ACCOUNTING_OMISSION=' && c.bytes.Load()==0'
ACCOUNTING_WITNESS='candidate accounting accepted payload, foreign, failed or unclosed stream'


def accounting(base,run,compiler,core,peer,environment,work,overlay=None):
    import json
    work=Path(work);work.mkdir(exist_ok=False)
    core=Path(core);target=core/ACCOUNTING_TARGET
    mapping={} if overlay is None else json.loads(Path(overlay).read_text())['Replace']
    original=Path(mapping.get(str(target),str(target)))
    body=original.read_text()
    if body.count(ACCOUNTING_OMISSION)!=1:raise ValueError('original zero-payload accounting guard changed')
    identity=base.COMMON.image_identity(peer)
    package=base.OWNER.PACKAGE
    parser=base.module('connected_peer_accounting_inventory',Path(__file__).with_name('test_node_chain_candidate_preparation.py'))
    parser.ROOTS={package:{ACCOUNTING_ROOT:ACCOUNTING_LEAVES}}
    expected={ACCOUNTING_ROOT,*[ACCOUNTING_ROOT+'/'+leaf for leaf in ACCOUNTING_LEAVES]}
    status,raw=run('peer-accounting',[compiler,'tool','test2json','-t','-p',package,peer,'-test.run=^'+ACCOUNTING_ROOT+'$','-test.count=1','-test.timeout=30s','-test.v'],core,45,environment)
    parser.verdict(raw.decode(),status,{package:expected})
    mutant=work/'accounting-mutant.go';mutant.write_text(body.replace(ACCOUNTING_OMISSION,''))
    mapping[str(target)]=str(mutant);projection=work/'overlay.json';projection.write_text(json.dumps({'Replace':mapping}))
    image=work/'peer-counter-control.test'
    status,_=run('peer-accounting-control-build',[compiler,'test','-c','-race','-p=1','-mod=readonly','-tags='+base.TAGS,'-ldflags=-checklinkname=0','-overlay='+str(projection),'-o',image,'./protocol/routervpnamnezia'],core,600,environment)
    if status:raise ValueError('peer accounting control failed compilation')
    status,raw=run('peer-accounting-control',[compiler,'tool','test2json','-t','-p',package,image,'-test.run=^'+ACCOUNTING_ROOT+'/payload$','-test.count=1','-test.timeout=30s','-test.v'],core,45,environment)
    base.OWNER.require_control(raw.decode(),status,{'cases':(ACCOUNTING_ROOT,ACCOUNTING_ROOT+'/payload'),'leaf':'payload','witness':ACCOUNTING_WITNESS})
    if original.read_text()!=body or base.COMMON.image_identity(peer)!=identity:raise ValueError('original accounting source or peer image changed')
    return {'records':len(expected),'control':'payload-guard-omission','candidate_counter':'exact-control-target-zero-payload-remote-EOF-and-owned-close'}
