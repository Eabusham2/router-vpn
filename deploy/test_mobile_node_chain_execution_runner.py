#!/usr/bin/env python3
"""Coverage/verdict controls for the bounded mobile execution component gate."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mobile_execution_gate',ROOT/'deploy/test_mobile_node_chain_execution.py')
G=importlib.util.module_from_spec(spec);spec.loader.exec_module(G)


class Runner(unittest.TestCase):
    def events(self):
        result=[]
        for package,names in G.inventory().items():
            def event(action,name=None):
                value={'Package':G.PREFIX+package,'Action':action}
                if name:value['Test']=name
                return value
            result.append(event('start'))
            for name in sorted(names):
                result.append(event('run',name))
                for child in {**G.ENTRY_CASES, **G.FACTORY_CASES}.get(name, ('original',)):
                    result.extend([event('run',name+'/'+child), event('pass',name+'/'+child)])
                result.append(event('pass',name))
            result.append(event('pass'))
        return result

    def check(self,events,code=0):
        return G.verdict('\n'.join(map(json.dumps,events)),code,G.inventory())

    def test_complete_exact_two_packages(self):
        self.assertEqual(len(self.check(self.events())),sum(1+len({**G.ENTRY_CASES, **G.FACTORY_CASES}.get(name, ('original',))) for names in G.inventory().values() for name in names))

    def test_typed_socks_roots_and_factory_control_are_mandatory(self):
        roots = {'TestRouterNodeChainExecutionBridgeSOCKS'+name for name in (
            'OriginalSource', 'OriginalFactory', 'LastRetainsChoiceWithoutProof')}
        self.assertTrue(roots.issubset(G.inventory()['experimental/libbox']))
        self.assertEqual(sum(control[0] == 'typed original SOCKS construction'
                             for control in G.CONTROLS), 1)
        for root in roots:
            events = [event for event in self.events()
                      if event.get('Test', '').split('/')[0] != root]
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.check(events)

    def test_typed_openvpn_roots_and_factory_control_are_mandatory(self):
        roots = {'TestRouterNodeChainExecutionBridgeOpenVPN'+name for name in (
            'OriginalSource', 'OriginalFactory', 'MobileSourceBoundary')}
        self.assertTrue(roots.issubset(G.inventory()['experimental/libbox']))
        controls = [control for control in G.CONTROLS if control[0] == 'typed original OpenVPN construction']
        self.assertEqual(len(controls), 1)
        self.assertEqual(controls[0][5], 'TestRouterNodeChainExecutionBridgeOpenVPNOriginalFactory/ordinary-server')
        boundary = [control for control in G.CONTROLS if control[0] == 'mobile OpenVPN source boundary']
        self.assertEqual(len(boundary), 1)
        self.assertEqual(boundary[0][5], 'TestRouterNodeChainExecutionBridgeOpenVPNMobileSourceBoundary/desktop-openvpn')
        for root in roots:
            events = [event for event in self.events()
                      if event.get('Test', '').split('/')[0] != root]
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.check(events)

    def test_execution_latency_bridge_roots_cannot_be_omitted(self):
        roots = {'TestRouterNodeChainExecutionBridgeLatency'+name for name in (
            'RequiresOriginalAssociation', 'RejectsUncapturedSharedService', 'CallerBounds',
            'PublicHandlePreservesBorrowedCleanup')}
        self.assertTrue(roots.issubset(G.inventory()['experimental/libbox']))
        for root in roots:
            events = [event for event in self.events() if not event.get('Test', '').startswith(root)]
            with self.subTest(root=root), self.assertRaises(ValueError):
                self.check(events)

    def test_closed_capture_typed_dispatch_root_cannot_be_omitted(self):
        root = 'TestRouterNodeChainExecutionBridgeLatencyClosedCaptureTypedDispatch'
        self.assertIn(root, G.inventory()['experimental/libbox'])
        events = [event for event in self.events()
                  if event.get('Test', '').split('/')[0] != root]
        with self.assertRaises(ValueError):
            self.check(events)

    def build_output(self, package='experimental/libbox', output=None):
        # Exact Go 1.26 record emitted by the hosted Darwin linker, before
        # the original libbox/daemon package start events.
        return {'ImportPath': G.PREFIX+package+'.test', 'Action': 'build-output',
                'Output': output if output is not None else
                '# '+G.PREFIX+package+'.test\nld: warning: ignoring duplicate libraries: \'-lobjc\'\n'}

    def test_actual_darwin_linker_records_preserve_exact_test_receipts(self):
        events=self.events()
        with_build=[]
        for event in events:
            if event['Action']=='start':
                with_build.append(self.build_output(event['Package'].removeprefix(G.PREFIX)))
            with_build.append(event)
        self.assertEqual(self.check(with_build),self.check(events))
        # Go may split build output over multiple records for one package.
        split=[self.build_output(output='linker warning, first fragment\n'),self.build_output()]+events
        self.assertEqual(self.check(split),self.check(events))

    def test_build_output_cannot_replace_missing_runtime_acceptance(self):
        events=self.events()
        for changed in ([self.build_output()], [self.build_output()]+events[:-1],
                        [self.build_output()]+[e for e in events if e.get('Action')!='run']):
            with self.assertRaises(ValueError):self.check(changed)

    def test_build_output_foreign_late_named_or_racing_refused(self):
        base=self.build_output()
        for changed in (dict(base,ImportPath=G.PREFIX+'foreign.test'),
                        dict(base,ImportPath=G.PREFIX+'experimental/libbox'),
                        dict(base,Package=G.PREFIX+'experimental/libbox'),
                        dict(base,Test='TestOtherOwner'),dict(base,Output='DATA RACE'),
                        dict(base,Output=None),dict(base,Output='')):
            with self.subTest(record=changed),self.assertRaises(ValueError):
                self.check([changed]+self.events())
        events=self.events()
        for position in (1,len(events)):
            changed=copy.deepcopy(events);changed.insert(position,base)
            with self.assertRaises(ValueError):self.check(changed)

    def test_build_output_bound_counts_all_fragments_and_utf8_bytes(self):
        exact='é'*(G.MAX_BUILD_OUTPUT_BYTES//2)
        self.assertEqual(self.check([self.build_output(output=exact)]+self.events()),self.check(self.events()))
        for diagnostics in ([self.build_output(output=exact+'x')],
                            [self.build_output(output=exact),self.build_output(output='x')]):
            with self.assertRaises(ValueError):self.check(diagnostics+self.events())

    def test_failed_build_runtime_failure_unknown_action_and_exit_still_refused(self):
        for action in ('build-fail','build-unknown'):
            with self.assertRaises(ValueError):
                self.check([dict(self.build_output(),Action=action)]+self.events())
        for action in ('fail','skip','unknown'):
            events=self.events();events[2]['Action']=action
            with self.assertRaises(ValueError):self.check([self.build_output()]+events)
        with self.assertRaises(ValueError):self.check([self.build_output()]+self.events(),1)

    def test_missing_root_or_terminal_package_refused(self):
        events=self.events()
        for changed in (events[:-1], [e for e in events if e.get('Test')!=next(iter(G.inventory()['daemon']))]):
            with self.assertRaises(ValueError):self.check(changed)

    def test_skip_race_nonzero_refused(self):
        for fault in ('skip','race','code'):
            events=self.events()
            if fault=='skip':events[2]['Action']='skip'
            if fault=='race':events.insert(3,dict(events[2],Action='output',Output='DATA RACE'))
            with self.assertRaises(ValueError):self.check(events,1 if fault=='code' else 0)

    def test_duplicate_and_late_child_refused(self):
        events=self.events()
        for position,event in ((2,events[1]),(5,dict(events[1],Test=events[1]['Test']+'/late'))):
            changed=copy.deepcopy(events);changed.insert(position,event)
            with self.assertRaises(ValueError):self.check(changed)

    def test_foreign_package_and_test_refused(self):
        for field,value in (('Package','github.com/foreign/native'),('Test','TestOtherOwner')):
            events=self.events();events[1][field]=value
            with self.assertRaises(ValueError):self.check(events)

    def test_parent_before_unjoined_child_refused(self):
        events=self.events();events[3],events[4]=events[4],events[3]
        with self.assertRaises(ValueError):self.check(events)

    def test_bounded_ordinary_race_only(self):
        command=G.command('go',G.inventory(),'^original$')
        self.assertIn('-race',command);self.assertIn('-timeout=180s',command)
        self.assertIn('./experimental/libbox',command);self.assertIn('./daemon',command)
        self.assertNotIn('routervpn_native_pq',G.TAGS)
        self.assertNotIn('routervpn_pq_traffic_test',G.TAGS)

    def test_causal_controls_touch_actual_unique_generated_functions(self):
        inverse={target:source for source,target in G.PREP.TEMPLATES.items()}
        for label,target,before,after,package,test,witness in G.CONTROLS:
            with self.subTest(label=label):
                if target=='daemon/instance.go':
                    raw=G.PREP.instance_source(G.PREP.FIELD_BEFORE+'}\n'+G.PREP.CLOSE_BEFORE+'\n'+G.PREP.CONSTRUCT_BEFORE+G.PREP.BOX_BEFORE+G.PREP.ACQUIRE_BEFORE+'}\n').decode()
                elif target=='experimental/libbox/routervpn_mtu_bridge.go':
                    raw=(ROOT/'mobile/mtu/bridge.go.tmpl').read_text()
                else:
                    raw=(ROOT/'mobile/chain_execution'/inverse[target]).read_text()
                self.assertEqual(raw.count(before),1)
                self.assertNotEqual(before,after)
                self.assertIn(test.split('/')[0],G.inventory()[package])
                self.assertTrue(witness)


    def test_entry_exact_roots_leaves_and_controls(self):
        self.assertEqual(len(G.ENTRY_CASES),4)
        self.assertEqual(sum(1+len(children) for children in G.ENTRY_CASES.values()),15)
        self.assertEqual(len(G.ENTRY_CONTROLS),5)
        self.assertEqual(sum(map(len,G.inventory().values()))-len(G.FACTORY_CASES),52)
        for root, children in G.ENTRY_CASES.items():
            for leaf in (root, *(root+'/'+child for child in children)):
                with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                    self.check([e for e in self.events() if e.get('Test') != leaf])
        root = next(iter(G.ENTRY_CASES))
        events = self.events()
        index = next(i for i,e in enumerate(events) if e.get('Test') == root and e['Action'] == 'pass')
        events[index:index] = [dict(events[index], Action='run', Test=root+'/foreign'), dict(events[index],Test=root+'/foreign')]
        with self.assertRaises(ValueError):self.check(events)

    def test_exported_selected_factory_all_outcomes_are_mandatory(self):
        self.assertEqual(G.FACTORY_CASES, {
            'TestRouterNodeChainExecutionBridgeCandidateSelectedFactory':
                ('server', 'compare-local', 'compare-server')})
        root = next(iter(G.FACTORY_CASES))
        for leaf in (root, *(root+'/'+child for child in G.FACTORY_CASES[root])):
            with self.subTest(leaf=leaf), self.assertRaises(ValueError):
                self.check([event for event in self.events() if event.get('Test') != leaf])
        events = self.events()
        index = next(i for i, event in enumerate(events)
                     if event.get('Test') == root and event['Action'] == 'pass')
        for name in (root+'/foreign-winner', root+'/server'):
            changed = copy.deepcopy(events)
            changed[index:index] = [dict(events[index], Action='run', Test=name),
                                    dict(events[index], Test=name)]
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check(changed)
        target = 'experimental/libbox/routervpn_node_chain_execution_candidates_live_test.go'
        self.assertEqual(G.PREP.TEMPLATES['candidates_live_test.go.tmpl'], target)
        source = (ROOT/'mobile/chain_execution/candidates_live_test.go.tmpl').read_text()
        for witness in ('RouterNodeChainExecutionNewCandidateMeasurement(',
                        'f.owner.BindNative(f.server)',
                        'started.StartOrReloadService(ctx,',
                        'b.RouterVPNNewNodeChainExecutionEngine(',
                        'f.owner.runWithFactory(', 'candidate.Prepare()',
                        'candidate.Close()', 'replacement.Prepare()',
                        '[]int32{0, 1}',
                        'NodeChainExecutionRemoteCandidateMeasurement',
                        'public candidate factory reran or replaced selected execution'):
            self.assertIn(witness, source)
        self.assertNotIn('reserveExecutionCandidateContext(', source)
        self.assertNotIn('executionCandidateBoundary', source)

    def control_events(self, control):
        _,_,_,_,package,test,witness=control
        root=test.split('/')[0]
        return [dict(Package=G.PREFIX+package,Action=action,**extra) for action,extra in (
            ('start',{}), ('run',{'Test':root}), ('run',{'Test':test}),
            ('output',{'Test':test,'Output':witness}), ('fail',{'Test':test}),
            ('fail',{'Test':root}), ('fail',{}))]

    def control_check(self, control, events, code=1):
        return G.entry_control_verdict('\n'.join(map(json.dumps,events)),code,control[4],control[5],control[6])

    def test_entry_controls_require_exact_normal_failure(self):
        for control in G.ENTRY_CONTROLS:
            events=self.control_events(control)
            self.assertTrue(self.control_check(control,events))
            for code in (0,-9,124,2):
                with self.subTest(control=control[0],code=code), self.assertRaises(ValueError):self.control_check(control,events,code)
            for index in range(len(events)):
                with self.subTest(control=control[0],omitted=index),self.assertRaises(ValueError):self.control_check(control,events[:index]+events[index+1:])
            for marker in ('DATA RACE','panic:','fatal error:','[build failed]','signal: killed','test timed out'):
                changed=copy.deepcopy(events);changed[3]['Output']+=' '+marker
                with self.assertRaises(ValueError):self.control_check(control,changed)
            for action in ('skip','pass'):
                changed=copy.deepcopy(events);changed[4]['Action']=action
                with self.assertRaises(ValueError):self.control_check(control,changed)
            for index in (0,1,2,4,5,6):
                with self.assertRaises(ValueError):self.control_check(control,events[:index]+[events[index]]+events[index:])
            changed=copy.deepcopy(events);changed[2]['Test']+='/foreign'
            with self.assertRaises(ValueError):self.control_check(control,changed)


if __name__=='__main__':unittest.main()
