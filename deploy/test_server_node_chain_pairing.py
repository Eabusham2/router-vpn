#!/usr/bin/env python3
"""Exercise private ordered pairing with actual schema1/2/3/4/5/6 policy compilers.

All filesystem transactions use the shipping pairer. --generate-fixtures writes
a private source-bound host artifact; --installed --fixtures requires that exact
artifact, the actual packaged pairer and the real offline agent checker, with no
Go compiler or network inside the image. In local mode the fixed agent command
is redirected only to the freshly built agent. When both
ROUTERVPN_ORDERED_PAIRING_NATIVE_CLI and ROUTERVPN_ORDERED_PAIRING_TOR_PACKAGE
are supplied, each staged registry also runs through the real offline native
checker and package verifier. No stage starts a lease, tunnel or Tor circuit.
"""
from pathlib import Path
from unittest import mock
import argparse
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
argument_parser = argparse.ArgumentParser(add_help=False)
argument_parser.add_argument('--generate-fixtures', type=Path)
argument_parser.add_argument('--installed', action='store_true')
argument_parser.add_argument('--fixtures', type=Path)
OPTIONS, remaining_arguments = argument_parser.parse_known_args()
if OPTIONS.generate_fixtures is not None and (OPTIONS.installed or OPTIONS.fixtures is not None):
    argument_parser.error('host generation cannot select installed fixtures')
if OPTIONS.installed != (OPTIONS.fixtures is not None):
    argument_parser.error('--installed requires --fixtures; source fixtures alone do not select installed acceptance')
sys.argv = [sys.argv[0], *remaining_arguments]
INSTALLED = OPTIONS.installed
PACKAGED_FILES = ('provision-multihop-relays.py', 'atomic-private-write.py', 'verified-regular-read.py')


def file_identity(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise AssertionError('validation input must be an original regular file')
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    after = path.lstat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after):
        raise AssertionError('validation input changed while being read')
    return {'size': before.st_size, 'sha256': digest.hexdigest()}


pairer_path = ROOT/'server/scripts/provision-multihop-relays.py'
if INSTALLED:
    if ROOT != Path('/routervpn-source'):
        raise AssertionError('installed acceptance requires the exact read-only source mount')
    packaged = Path('/usr/local/lib/router-vpn-relay')
    for name in PACKAGED_FILES:
        if file_identity(packaged/name) != file_identity(ROOT/'server/scripts'/name):
            raise AssertionError('installed pairer or helper differs from the bound source')
    pairer_path = packaged/'provision-multihop-relays.py'
spec = importlib.util.spec_from_file_location('private_ordered_pairer', pairer_path)
PAIR = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PAIR)

# Generate real complete private inputs from the original native source
# fixtures, rather than inventing a descriptor or copying an old JSON sample.
GENERATOR = r'''package mobilemultihop
import (
 "fmt"
 "encoding/json"
 "os"
 "testing"
 "router-vpn/internal/multihoprelay"
)
func TestRouterVPNOperatorPairingSources(t *testing.T) {
 path := os.Getenv("ROUTERVPN_ORDERED_PAIRING_FIXTURES")
 if path == "" { t.Fatal("private fixture output is required") }
 type row struct {
  Name string `json:"name"`
  Source NodeChainServerSource `json:"source"`
  SourceJSON string `json:"source_json"`
  Reference multihoprelay.NodeChainDescriptor `json:"reference"`
 }
 rows := []row{}
 add := func(name string, policy *NodeChainServerPolicy) {
  var source NodeChainServerSource
  if json.Unmarshal([]byte(policy.Source()), &source) != nil { t.Fatal("canonical fixture source") }
  rows = append(rows, row{name, source, policy.Source(), policy.Descriptor()})
 }
 paired, _ := nodeChainServerFixture(t, 3, "")
 add("paired", paired)
 for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
  for _, layer := range []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
   _, policy, _ := nodeChainImportedServerFixture(t, mode, layer)
   add(mode+"/"+layer, policy)
  }
 }
 _, selected, _ := nodeChainImportedServerFixture(t, "wg", "")
 var source NodeChainServerSource
 if json.Unmarshal([]byte(selected.Source()), &source) != nil { t.Fatal("selected source") }
 last := len(source.Nodes)-1
 node, err := ParseNodeLaunchInput(source.Nodes[last]); if err != nil { t.Fatal(err) }
 profile := predecessorCopy(node.profile)
 profile["dns_mode"], profile["dns_protocol"], profile["dns_host"], profile["dns_port"] = "custom", "tcp", "9.9.9.9", float64(5353)
 node, err = NewNodeProfile(node.mode, node.inputs.Files, startJSON(t, profile), node.inputs.Start, node.inputs.DNSBootstrap)
 if err != nil { t.Fatal(err) }
 source.Nodes[last], err = node.LaunchInput(); if err != nil { t.Fatal(err) }
 changed, err := NewNodeChainServerPolicy(startJSON(t, source)); if err != nil { t.Fatal(err) }
 add("wg/custom-dns", changed)
 type digestRow struct { Schema int `json:"schema"`; Text string `json:"text"`; Digest string `json:"digest"` }
 vectors := []digestRow{}
 for _, schema := range []int{1, 2, 3, 4, 5, 6} {
  for _, text := range []string{selected.Source(), "private<&>\\tail", "private\u2028line\u2029tail", "private-雪"} {
   domain := fmt.Sprintf("routervpn-server-node-chain-source-v%d", schema)
   raw, err := json.Marshal([]string{domain, text}); if err != nil { t.Fatal(err) }
   vectors = append(vectors, digestRow{schema, text, externalDigest(raw)})
  }
 }
 type planRow struct { Name string `json:"name"`; Plan map[string]any `json:"plan"`; SourceJSON string `json:"source_json"`; Reference multihoprelay.NodeChainDescriptor `json:"reference"` }
 plans := []planRow{}
 addPlan := func(name string, plan map[string]any) {
  policy, err := NewNodeChainServerPlan(startJSON(t, plan)); if err != nil { t.Fatal("complete private plan fixture", name, err) }
  plans = append(plans, planRow{name, plan, policy.Source(), policy.Descriptor()})
 }
 for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
  for _, imported := range []bool{false, true} {
   plan, _ := nodeChainServerPlanFixture(t, mode, "", imported)
   suffix := "paired"; if imported { suffix = "imported" }
   addPlan(mode+"/"+suffix, plan)
  }
 }
 plan, _ := nodeChainServerPlanFixture(t, "wg", "", true)
 finalSelection := plan["members"].([]any)[1].(map[string]any)["paired"].(map[string]any)
 finalProfile := finalSelection["bundle"].(map[string]any)["routerProfiles"].([]any)[0].(map[string]any)
 finalProfile["dns_mode"], finalProfile["dns_protocol"], finalProfile["dns_host"], finalProfile["dns_port"] = "custom", "https", "captured-query.example", float64(5443)
 finalProfile["dns_server_name"], finalProfile["dns_path"] = "captured-query.example", "/original-query"
 finalSelection["dns_bootstrap"] = startJSON(t, map[string]any{"server": map[string]any{"type": "udp", "tag": "external-dns-bootstrap", "server": "9.9.9.9", "server_port": 5553, "detour": "proxy"}, "query": map[string]any{"server": "external-dns-bootstrap", "strategy": "ipv4_only", "disable_cache": true}})
 addPlan("wg/imported-bootstrap", plan)
 for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
  for _, protocol := range []string{"http-connect", "https-connect"} {
   original := connectServerPlanFixture(t, mode, protocol)
   policy, err := NewNodeChainCONNECTServerPlan(startJSON(t, original)); if err != nil { t.Fatal("original typed CONNECT plan", err) }
   name := "connect/"+mode+"/"+protocol
   add(name, policy)
   plans = append(plans, planRow{name, original, policy.Source(), policy.Descriptor()})
  }
 }
 for _, count := range []int{4, 8} {
  for _, protocol := range []string{"http-connect", "https-connect"} {
   _, original := connectExecutionPrefixPlanFixture(t, count, "wg", protocol)
   policy, err := NewNodeChainCONNECTServerPlan(startJSON(t, original)); if err != nil { t.Fatal("complete typed CONNECT prefix plan", err) }
   name := "connect-prefix/"+fmt.Sprint(count)+"/"+protocol
   add(name, policy)
   plans = append(plans, planRow{name, original, policy.Source(), policy.Descriptor()})
  }
 }
 for count := 3; count <= 8; count++ {
  mode := []string{"wg", "awg2-fast", "awg2-strong"}[(count-3)%3]
  _, original := socksExecutionPrefixPlanFixture(t, count, mode, "password")
  policy, err := NewNodeChainSOCKSServerPlan(startJSON(t, original)); if err != nil { t.Fatal("complete typed SOCKS prefix plan", err) }
  name := "socks-prefix/"+fmt.Sprint(count)+"/"+mode
  add(name, policy)
  plans = append(plans, planRow{name, original, policy.Source(), policy.Descriptor()})
 }
 for i,mode := range []string{"wg","awg2-fast","awg2-strong"} {
  for _,network := range []string{"tcp","udp"} {
   count:=1; if network=="udp" {count=6}
   layer:=[]string{"","aes-256-gcm","aes-256-gcm+xor-whitening"}[i]
   _,original:=nodeChainOpenVPNServerPlanFixture(t,count,mode,network,layer)
   policy,err:=NewNodeChainOpenVPNServerPlan(startJSON(t,original));if err!=nil {t.Fatal("original typed OpenVPN plan",err)}
   name:="openvpn/"+mode+"/"+network
   add(name,policy)
   plans=append(plans,planRow{name,original,policy.Source(),policy.Descriptor()})
  }
 }
 for _, mode := range []string{"wg", "awg2-fast", "awg2-strong"} {
  for index, layout := range []nodeChainImportedLayout{{"adjacent",4,[]int{1,2}}, {"separated",5,[]int{1,3}}, {"packet-first",5,[]int{2,3}}, {"maximum",8,[]int{1,4,6}}} {
   layer := []string{"", "aes-256-gcm", "aes-256-gcm+xor-whitening"}[index%3]
   original, _ := multipleImportedServerPlanFixture(t, layout, mode, layer)
   policy, err := NewNodeChainMultipleImportedServerPlan(startJSON(t, original)); if err != nil { t.Fatal("complete independent imported Server plan", err) }
   name := "multiple/"+mode+"/"+layout.name
   add(name, policy)
   plans = append(plans, planRow{name,original,policy.Source(),policy.Descriptor()})
  }
 }
 encoded, err := json.Marshal(struct{ Rows []row `json:"rows"`; Digests []digestRow `json:"digests"`; Plans []planRow `json:"plans"` }{rows, vectors, plans}); if err != nil { t.Fatal(err) }
 if err = os.WriteFile(path, encoded, 0600); err != nil { t.Fatal(err) }
}
'''

CHECKER = r'''package main
import (
 "os"
 "strconv"
 "testing"
)
func TestRouterVPNOperatorOrderedStagedRegistry(t *testing.T) {
 registry, agent := os.Getenv("ROUTERVPN_ORDERED_PAIRING_REGISTRY"), os.Getenv("ROUTERVPN_ORDERED_PAIRING_AGENT_CONFIG")
 if registry == "" || agent == "" { t.Fatal("exact staged registry and entry are required") }
 expected, err := strconv.Atoi(os.Getenv("ROUTERVPN_ORDERED_PAIRING_EXPECTED")); if err != nil { t.Fatal(err) }
 count, err := checkRelayRegistryWithPaths(registry, agent, relayRegistryCheckPaths{
  torSources: os.Getenv("ROUTERVPN_ORDERED_PAIRING_TOR_SOURCES"),
  nodeChainSources: os.Getenv("ROUTERVPN_ORDERED_PAIRING_SOURCES"),
  packagePrefix: os.Getenv("ROUTERVPN_ORDERED_PAIRING_TOR_PACKAGE"),
  core: os.Getenv("ROUTERVPN_ORDERED_PAIRING_NATIVE_CLI"), temporary: t.TempDir(),
 })
 if err != nil || count != expected { t.Fatal("real offline registry checker rejected exact staged sources", count, err) }
}
'''

READER = r'''package main
import (
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 "time"
 "router-vpn/internal/mobilemultihop"
 "router-vpn/internal/multihoprelay"
)
func TestRouterVPNOperatorOriginalPrivateReader(t *testing.T) {
 raw, err := os.ReadFile(os.Getenv("ROUTERVPN_ORDERED_PAIRING_FIXTURES")); if err != nil { t.Fatal(err) }
 var input struct { Rows []struct { Name string `json:"name"`; SourceJSON string `json:"source_json"`; Reference multihoprelay.NodeChainDescriptor `json:"reference"` } `json:"rows"` }
 if json.Unmarshal(raw, &input) != nil || len(input.Rows) != 45 { t.Fatal("complete original source fixture inventory") }
 directory := t.TempDir()
 runner := &relayNodeChainExecRunner{sources:directory}
 connect, socks, openvpn, multiple := 0, 0, 0, 0
 for _, row := range input.Rows {
  t.Run(row.Name, func(t *testing.T) {
   path := filepath.Join(directory, row.Reference.SourceSHA256+".json")
   if atomicWritePrivilegedState(path, []byte(row.SourceJSON)) != nil { t.Fatal("private original source") }
   policy, err := runner.source(row.Reference, row.Reference.EntryNodeID)
   if err != nil || policy.Source() != row.SourceJSON { t.Fatal("installed reader did not retain original typed policy", err) }
   capture, err := relayNodeChainValidationCapture(row.Reference, "10.77.0.1", "10.77.0.2", 26240, time.Now().UTC())
   if err != nil { t.Fatal("original offline parser capture", err) }
   if _, err = policy.NativeConfig(capture); err != nil { t.Fatal("original parser configuration", err) }
   if row.Reference.Schema == 3 {
    socks++
    if _, err = mobilemultihop.NewNodeChainServerPolicy(row.SourceJSON); err == nil { t.Fatal("generic compiler admitted SOCKS") }
    if _, err = mobilemultihop.NewNodeChainCONNECTServerPolicy(row.SourceJSON); err == nil { t.Fatal("CONNECT compiler admitted SOCKS") }
    if len(capture.Request.LocalPacketPublicKeys) != len(row.Reference.Members)-1 || len(capture.Request.LocalPacketPositions) != len(row.Reference.Members)-1 || policy.NativeCarrierRequired() != (len(row.Reference.Members)>2) { t.Fatal("SOCKS suffix lost original packet authority") }
    for i, position := range capture.Request.LocalPacketPositions { if position != i { t.Fatal("SOCKS prefix position changed") } }
    changed := row.Reference.Clone(); changed.Schema = 4
    if _, err = runner.source(changed, changed.EntryNodeID); err == nil { t.Fatal("SOCKS source fell back to CONNECT") }
   }
   if row.Reference.Schema == 4 {
    connect++
    if _, err = mobilemultihop.NewNodeChainServerPolicy(row.SourceJSON); err == nil { t.Fatal("generic compiler admitted CONNECT") }
    if len(capture.Request.LocalPacketPublicKeys) != len(row.Reference.Members)-1 || len(capture.Request.LocalPacketPositions) != len(row.Reference.Members)-1 || policy.NativeCarrierRequired() != (len(row.Reference.Members)>2) { t.Fatal("CONNECT suffix lost original packet authority") }; for i,position := range capture.Request.LocalPacketPositions { if position!=i {t.Fatal("CONNECT prefix position changed")} }
    changed := row.Reference.Clone(); changed.Schema = 2
    if _, err = runner.source(changed, changed.EntryNodeID); err == nil { t.Fatal("CONNECT source fell back to SS") }
   }
   if row.Reference.Schema == 5 {
    openvpn++
    if _,err=mobilemultihop.NewNodeChainServerPolicy(row.SourceJSON);err==nil {t.Fatal("generic compiler admitted OpenVPN")}
    if _,err=mobilemultihop.NewNodeChainSOCKSServerPolicy(row.SourceJSON);err==nil {t.Fatal("SOCKS compiler admitted OpenVPN")}
    if _,err=mobilemultihop.NewNodeChainCONNECTServerPolicy(row.SourceJSON);err==nil {t.Fatal("CONNECT compiler admitted OpenVPN")}
    if len(capture.Request.LocalPacketPublicKeys)!=len(row.Reference.Members)-1||len(capture.Request.LocalPacketPositions)!=len(row.Reference.Members)-1||policy.NativeCarrierRequired()!=(len(row.Reference.Members)>2){t.Fatal("OpenVPN original packet authority changed")}
    for i,position:=range capture.Request.LocalPacketPositions {if position!=i {t.Fatal("OpenVPN prefix position changed")}}
    if _,state,err:=policy.ReadOpenVPNServerCapture(capture);err!=nil||state.Middle.ConfiguredMTU<1280 {t.Fatal("OpenVPN native configuration lost",err)}
    changed:=row.Reference.Clone();changed.Schema=4
    if _,err=runner.source(changed,changed.EntryNodeID);err==nil {t.Fatal("OpenVPN source fell back to CONNECT")}
   }
   if row.Reference.Schema == 6 {
    multiple++
    for _, parse := range []func(string)(*mobilemultihop.NodeChainServerPolicy,error){mobilemultihop.NewNodeChainServerPolicy,mobilemultihop.NewNodeChainSOCKSServerPolicy,mobilemultihop.NewNodeChainCONNECTServerPolicy,mobilemultihop.NewNodeChainOpenVPNServerPolicy} {
     if _,err=parse(row.SourceJSON);err==nil {t.Fatal("independent imports entered a singleton compiler")}
    }
    positions, public := []int{0}, 0
    for index,member := range row.Reference.Members {
     if member.NodeKind=="external" {public++; if member.NodeID!=""||member.ClientPublicKey!=""||member.ServerPublicKey!=""||member.ProofKind!="public-path" {t.Fatal("import acquired packet or private proof identity")}}
     if index<len(row.Reference.Members)-1&&member.NodeKind=="" {positions=append(positions,member.Position)}
    }
    if public<2||len(positions)!=len(capture.Request.LocalPacketPositions)||len(positions)!=len(capture.Request.LocalPacketPublicKeys)||policy.NativeCarrierRequired()!=(row.Reference.Members[0].NodeKind=="") {t.Fatal("multiple-import original sparse packet authority changed")}
    for index,position:=range positions {if capture.Request.LocalPacketPositions[index]!=position {t.Fatal("multiple-import packet position changed")}}
    changed:=row.Reference.Clone();changed.Schema=2
    if _,err=runner.source(changed,changed.EntryNodeID);err==nil {t.Fatal("multiple imports fell back to singleton SS")}
   }
   if atomicWritePrivilegedState(path, []byte("{}")) != nil { t.Fatal("private replacement source") }
   if _, err = runner.source(row.Reference, row.Reference.EntryNodeID); err == nil { t.Fatal("reader retained a changed source") }
  })
 }
 if openvpn != 6 { t.Fatal("missing original OpenVPN reader cases") }
 if socks != 6 { t.Fatal("missing original SOCKS reader cases") }
 if connect != 10 { t.Fatal("missing original CONNECT reader cases") }
 if multiple != 12 { t.Fatal("missing complete multiple-import reader cases") }
}
'''

CONNECT_NAMES = tuple('connect/'+mode+'/'+protocol for mode in ('wg', 'awg2-fast', 'awg2-strong')
                      for protocol in ('http-connect', 'https-connect')) + tuple('connect-prefix/'+str(count)+'/'+protocol for count in (4, 8) for protocol in ('http-connect', 'https-connect'))
SOCKS_NAMES = tuple('socks-prefix/'+str(count)+'/'+('wg', 'awg2-fast', 'awg2-strong')[(count-3)%3] for count in range(3, 9))
OPENVPN_NAMES = tuple('openvpn/'+mode+'/'+network for mode in ('wg', 'awg2-fast', 'awg2-strong') for network in ('tcp', 'udp'))
MULTIPLE_IMPORTED_NAMES = tuple('multiple/'+mode+'/'+layout for mode in ('wg', 'awg2-fast', 'awg2-strong')
                                for layout in ('adjacent', 'separated', 'packet-first', 'maximum'))
FIXTURE_NAMES = ('paired', 'wg/', 'wg/aes-256-gcm', 'wg/aes-256-gcm+xor-whitening',
                 'awg2-fast/', 'awg2-fast/aes-256-gcm', 'awg2-fast/aes-256-gcm+xor-whitening',
                 'awg2-strong/', 'awg2-strong/aes-256-gcm', 'awg2-strong/aes-256-gcm+xor-whitening',
                 'wg/custom-dns', *CONNECT_NAMES, *SOCKS_NAMES, *OPENVPN_NAMES, *MULTIPLE_IMPORTED_NAMES)
PLAN_NAMES = ('wg/paired', 'wg/imported', 'awg2-fast/paired', 'awg2-fast/imported',
              'awg2-strong/paired', 'awg2-strong/imported', 'wg/imported-bootstrap', *CONNECT_NAMES, *SOCKS_NAMES, *OPENVPN_NAMES, *MULTIPLE_IMPORTED_NAMES)
SOURCE_DIRECTORIES = ('cmd/router-agent', 'internal', 'server/scripts')
SOURCE_FILES = ('go.mod', 'go.sum', 'deploy/router-agent.Dockerfile', 'deploy/test_server_node_chain_pairing.py')
FIXTURE_BYTES_LIMIT = 16 << 20


def source_manifest():
    # This source tree may have no external module sums. Re-enumerating this
    # optional path still detects later creation/removal; links stay invalid.
    # Keep go.sum in SOURCE_FILES for Git cleanliness and output exclusions.
    paths = {ROOT/name for name in SOURCE_FILES
             if name != 'go.sum' or os.path.lexists(ROOT/name)}
    for name in SOURCE_DIRECTORIES:
        directory = ROOT/name
        if directory.is_symlink() or not directory.is_dir():
            raise AssertionError('original fixture source directory is unavailable')
        for path in directory.rglob('*'):
            if '__pycache__' in path.parts or path.suffix == '.pyc':
                continue
            if path.is_symlink():
                raise AssertionError('original fixture source includes a linked path')
            if path.is_file():
                paths.add(path)
    return {str(path.relative_to(ROOT)): file_identity(path) for path in sorted(paths)}


def fixture_payload_bytes(rows, digests, plans):
    return json.dumps({'rows': rows, 'digests': digests, 'plans': plans}, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()


def validate_fixture_inventory(value):
    if not isinstance(value, dict) or set(value) != {'rows', 'digests', 'plans'} or not isinstance(value['rows'], list) or not isinstance(value['digests'], list) or not isinstance(value['plans'], list):
        raise AssertionError('actual compiler fixture envelope changed')
    rows = value['rows']
    if len(rows) != len(FIXTURE_NAMES) or tuple(row.get('name') for row in rows if isinstance(row, dict)) != FIXTURE_NAMES:
        raise AssertionError('actual compiler fixture inventory changed')
    for row in rows:
        if set(row) != {'name', 'source', 'source_json', 'reference'} or not isinstance(row['source'], dict) or not isinstance(row['reference'], dict) or not isinstance(row['source_json'], str):
            raise AssertionError('actual compiler fixture row changed')
        if PAIR.decode(row['source_json'].encode()) != row['source']:
            raise AssertionError('fixture source differs from its canonical original')
        reference, source = row['reference'], row['source']
        if any(reference.get(name) != source.get(name) for name in ('schema', 'entry_id', 'entry_node_id', 'entry_mode')):
            raise AssertionError('fixture descriptor changed its original entry')
        if PAIR.node_chain_source_digest(row['source_json'], source.get('schema')) != reference.get('source_sha256'):
            raise AssertionError('fixture descriptor changed its exact source digest')
    vectors = value['digests']
    if len(vectors) != 24 or [row.get('schema') for row in vectors if isinstance(row, dict)] != [1]*4+[2]*4+[3]*4+[4]*4+[5]*4+[6]*4:
        raise AssertionError('original Go digest vector inventory changed')
    for row in vectors:
        if set(row) != {'schema', 'text', 'digest'} or not isinstance(row['text'], str) or not isinstance(row['digest'], str) or not re.fullmatch('[0-9a-f]{64}', row['digest']):
            raise AssertionError('original Go digest vector changed')
    plans = value['plans']
    if len(plans) != len(PLAN_NAMES) or tuple(row.get('name') for row in plans if isinstance(row, dict)) != PLAN_NAMES:
        raise AssertionError('actual bundle plan fixture inventory changed')
    for row in plans:
        if set(row) != {'name', 'plan', 'source_json', 'reference'} or not isinstance(row['plan'], dict) or not isinstance(row['source_json'], str) or not isinstance(row['reference'], dict):
            raise AssertionError('actual bundle plan fixture changed')
        source = PAIR.decode(row['source_json'].encode())
        if row['plan'].get('entry_node_id') != row['reference'].get('entry_node_id') or PAIR.node_chain_source_digest(row['source_json'], source.get('schema')) != row['reference'].get('source_sha256'):
            raise AssertionError('actual bundle plan lost its compiled source identity')
    return value


def generate_fixtures(destination):
    destination = destination.absolute()
    if any(destination == ROOT/name or ROOT/name in destination.parents for name in (*SOURCE_DIRECTORIES, *SOURCE_FILES)):
        raise AssertionError('private fixture output cannot replace captured source')
    before = source_manifest()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, timeout=10).decode().strip()
    if not re.fullmatch('[0-9a-f]{40}', commit):
        raise AssertionError('fixture generation requires an exact source commit')
    changes = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all', '--', *SOURCE_DIRECTORIES, *SOURCE_FILES], cwd=ROOT, timeout=10)
    with tempfile.TemporaryDirectory(prefix='ordered-pairing-generator-') as temporary:
        directory = Path(temporary)
        generator, output, overlay = directory/'fixture_test.go', directory/'fixtures.json', directory/'fixture-overlay.json'
        generator.write_text(GENERATOR)
        overlay.write_text(json.dumps({'Replace': {str(ROOT/'internal/mobilemultihop/routervpn_operator_pairing_fixture_test.go'): str(generator)}}))
        subprocess.run(['go', 'test', '-count=1', '-overlay='+str(overlay), '-run=^TestRouterVPNOperatorPairingSources$', './internal/mobilemultihop'],
                       cwd=ROOT, env=dict(os.environ, ROUTERVPN_ORDERED_PAIRING_FIXTURES=str(output)), check=True, timeout=120)
        raw = output.read_bytes()
        if not raw or len(raw) > FIXTURE_BYTES_LIMIT:
            raise AssertionError('private generated fixture exceeded its fixed bound')
        data = validate_fixture_inventory(PAIR.decode(raw))
    if source_manifest() != before:
        raise AssertionError('original source changed during actual fixture generation')
    envelope = dict(schema=1, kind='routervpn-private-ordered-pairing-fixtures', source_sha=commit, source_clean=not bool(changes),
                    source_manifest=before, generator_sha256=hashlib.sha256(GENERATOR.encode()).hexdigest(),
                    payload_sha256=hashlib.sha256(fixture_payload_bytes(data['rows'], data['digests'], data['plans'])).hexdigest(), **data)
    encoded = json.dumps(envelope, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
    if len(encoded) > FIXTURE_BYTES_LIMIT:
        raise AssertionError('private fixture artifact exceeded its fixed bound')
    _, write, _ = PAIR.helpers()
    write(destination, encoded)
    return envelope


def read_fixtures(path, installed=False):
    identity = file_identity(path)
    if not identity['size'] or identity['size'] > FIXTURE_BYTES_LIMIT or stat.S_IMODE(path.lstat().st_mode) != 0o600:
        raise AssertionError('ordered fixtures require a bounded private source artifact')
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != identity['sha256']:
        raise AssertionError('ordered fixture artifact changed during capture')
    value = PAIR.decode(raw)
    fields = {'schema', 'kind', 'source_sha', 'source_clean', 'source_manifest', 'generator_sha256', 'payload_sha256', 'rows', 'digests', 'plans'}
    if not isinstance(value, dict) or set(value) != fields or type(value.get('schema')) is not int or value['schema'] != 1 or value.get('kind') != 'routervpn-private-ordered-pairing-fixtures':
        raise AssertionError('ordered fixture source envelope changed')
    if not isinstance(value['source_sha'], str) or not re.fullmatch('[0-9a-f]{40}', value['source_sha']) or type(value['source_clean']) is not bool:
        raise AssertionError('ordered fixture source identity is invalid')
    if value['source_manifest'] != source_manifest() or value['generator_sha256'] != hashlib.sha256(GENERATOR.encode()).hexdigest():
        raise AssertionError('ordered fixture source does not match the exact mounted checkout')
    data = validate_fixture_inventory({'rows': value['rows'], 'digests': value['digests'], 'plans': value['plans']})
    if value['payload_sha256'] != hashlib.sha256(fixture_payload_bytes(data['rows'], data['digests'], data['plans'])).hexdigest():
        raise AssertionError('ordered fixture payload differs from its original capture')
    if installed and (not value['source_clean'] or value['source_sha'] != os.environ.get('ROUTERVPN_ORDERED_PAIRING_SOURCE_SHA')):
        raise AssertionError('installed acceptance requires the exact clean dispatched source')
    return value


class ServerNodeChainPairing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = tempfile.TemporaryDirectory(prefix='ordered-pairing-tools-')
        cls.real_run = staticmethod(subprocess.run)
        root = Path(cls.tools.name)
        cls.agent, cls.native_checker, cls.native_checks = root/'router-vpn-agent', None, 0
        cls.source_before = source_manifest()
        if INSTALLED:
            cls.agent = Path('/usr/local/bin/router-vpn-agent')
            cls.installed_images = {str(path): file_identity(path) for path in (cls.agent, Path('/usr/local/bin/sing-box'))}
            generated = read_fixtures(OPTIONS.fixtures, installed=True)
        else:
            subprocess.run(['go', 'build', '-buildvcs=false', '-o', str(cls.agent), './cmd/router-agent'], cwd=ROOT, check=True, timeout=120)
            output = root/'fixtures.json'
            generate_fixtures(output)
            generated = read_fixtures(output)
            reader, overlay = root/'reader_test.go', root/'reader-overlay.json'
            reader.write_text(READER)
            overlay.write_text(json.dumps({'Replace': {str(ROOT/'cmd/router-agent/routervpn_operator_original_private_reader_test.go'): str(reader)}}))
            checked = subprocess.run(['go', 'test', '-json', '-count=1', '-overlay='+str(overlay),
                                      '-run=^TestRouterVPNOperatorOriginalPrivateReader$', './cmd/router-agent'],
                                     cwd=ROOT, env=dict(os.environ, ROUTERVPN_ORDERED_PAIRING_FIXTURES=str(output)),
                                     check=True, timeout=120, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            events = [json.loads(line) for line in checked.stdout.splitlines()]
            required = {'TestRouterVPNOperatorOriginalPrivateReader',
                        *('TestRouterVPNOperatorOriginalPrivateReader/'+name for name in FIXTURE_NAMES)}
            for action in ('run', 'pass'):
                observed = [event['Test'] for event in events if event.get('Action') == action and 'Test' in event]
                if len(observed) != len(required) or set(observed) != required:
                    raise AssertionError('actual private reader did not execute the exact original source inventory')
            if any(event.get('Action') in ('fail', 'skip') for event in events):
                raise AssertionError('actual private reader did not complete')
        cls.fixtures = {row['name']: row for row in generated['rows']}
        cls.plans = {row['name']: row for row in generated['plans']}
        cls.digest_vectors = generated['digests']
        if tuple(cls.fixtures) != FIXTURE_NAMES:
            raise AssertionError('actual compiler fixture inventory changed')
        cls.node = cls.fixtures['wg/']['source']['entry_node_id']
        if any(row['source']['entry_node_id'] != cls.node for row in cls.fixtures.values()) or any(row['plan']['entry_node_id'] != cls.node for row in cls.plans.values()):
            raise AssertionError('source fixtures must retain the same original entry')
        if INSTALLED:
            return
        core, package = os.environ.get('ROUTERVPN_ORDERED_PAIRING_NATIVE_CLI'), os.environ.get('ROUTERVPN_ORDERED_PAIRING_TOR_PACKAGE')
        if bool(core) != bool(package):
            raise AssertionError('full offline native validation requires both actual core and Tor package')
        if core:
            checker = root/'checker_test.go'
            overlay = root/'checker-overlay.json'
            checker.write_text(CHECKER)
            overlay.write_text(json.dumps({'Replace': {str(ROOT/'cmd/router-agent/routervpn_operator_ordered_staged_test.go'): str(checker)}}))
            cls.native_checker = root/'registry-check.test'
            subprocess.run(['go', 'test', '-c', '-overlay='+str(overlay), '-o', str(cls.native_checker), './cmd/router-agent'], cwd=ROOT, check=True, timeout=120)

    @classmethod
    def tearDownClass(cls):
        try:
            if source_manifest() != cls.source_before:
                raise AssertionError('operator pairing tests changed their original source')
            if INSTALLED:
                if cls.native_checks == 0 or any(file_identity(Path(path)) != identity for path, identity in cls.installed_images.items()):
                    raise AssertionError('installed pairing lost actual native checks or changed its binaries')
                for name in PACKAGED_FILES:
                    if file_identity(Path('/usr/local/lib/router-vpn-relay')/name) != file_identity(ROOT/'server/scripts'/name):
                        raise AssertionError('installed pairer or helper changed during acceptance')
        finally:
            cls.tools.cleanup()

    def compile(self, source, command='compile-server-node-chain-source'):
        result = self.real_run([str(self.agent), command], input=json.dumps(dict(entry_node_id=self.node, source=source)).encode(),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=20)
        return json.loads(result.stdout)

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(prefix='private-ordered-pairing-')
        self.root = Path(self.case.name)
        self.registry, self.agent_config, self.input = (self.root/name for name in ('registry.json', 'agent.json', 'source.json'))
        self.sources, self.tor_sources = self.root/'node-chain-sources', self.root/'tor-sources'
        self.sources.mkdir(mode=0o700)
        self.tor_sources.mkdir(mode=0o700)
        self.read, self.write, _ = PAIR.helpers()
        self.write(self.agent_config, json.dumps(dict(node_id=self.node, tunnel_cidrs=['10.77.0.0/24'])).encode())
        self.selected = copy.deepcopy(self.fixtures['wg/'])
        self.write(self.input, json.dumps(self.selected['source']).encode())
        self.previous = copy.deepcopy(self.fixtures['paired'])
        self.previous_path = self.sources/(self.previous['reference']['source_sha256']+'.json')
        self.write(self.previous_path, self.previous['source_json'].encode())
        self.tor = self.compile(dict(schema=1, id='preserved-tor', entry_node_id=self.node, mode='tor', dns=dict(mode='home'), adguard_ipv4='192.168.50.133'), 'compile-server-tor-source')
        self.tor_path = self.tor_sources/(self.tor['reference']['source_sha256']+'.json')
        self.write(self.tor_path, self.tor['source_json'].encode())
        self.foreign = dict(id='preserved-proxy', mode='shadowsocks', node_id='b'*64, dns_server='10.88.0.1',
                            transport=dict(type='shadowsocks', tag='exit', server='198.51.100.2', server_port=8388,
                                           method='aes-256-gcm', password='private-preserved-proxy-key'))
        self.original = dict(listen_ip='10.77.0.1', first_port=26240, last_port=26271, ttl_seconds=90,
                             exits=[self.foreign], tor_exits=[self.tor['reference']], node_chains=[self.previous['reference']])
        self.write(self.registry, PAIR.registry_bytes(self.original))
        self.unrelated = self.sources/'operator-unreferenced.json'
        self.write(self.unrelated, b'{"private":"preserve-unrelated-source"}')
        self.before = self.registry.read_bytes()
        self.saved = {path: (path.read_bytes(), path.stat().st_ino) for path in (self.previous_path, self.tor_path, self.unrelated)}
        self.on_check, self.compiler_change, self.checks = None, None, 0
        self.output = io.StringIO()

    def tearDown(self):
        self.case.cleanup()

    def execute(self, command, **kwargs):
        self.assertEqual(command[0], '/usr/local/bin/router-vpn-agent')
        self.assertIs(kwargs['stderr'], subprocess.DEVNULL)
        self.assertTrue(kwargs['check'])
        self.assertNotIn('shell', kwargs)
        if command[1] in ('compile-server-node-chain-source', 'compile-server-node-chain-plan', 'compile-server-tor-source'):
            self.assertEqual(len(command), 2)
            self.assertEqual(kwargs['timeout'], 20)
            self.assertIs(kwargs['stdout'], subprocess.PIPE)
            result = self.real_run([str(self.agent), command[1]], **kwargs)
            if self.compiler_change is not None and command[1] in ('compile-server-node-chain-source', 'compile-server-node-chain-plan'):
                value = json.loads(result.stdout)
                self.compiler_change(value)
                result.stdout = json.dumps(value).encode()
            return result
        self.assertEqual(command[1], 'check-multihop-registry')
        self.assertEqual(len(command), 6)
        self.assertEqual(kwargs['timeout'], 60)
        self.assertIs(kwargs['stdout'], subprocess.DEVNULL)
        self.checks += 1
        stage, tor_sources, ordered_sources = Path(command[2]), Path(command[4]), Path(command[5])
        self.assertEqual(stage.stat().st_mode & 0o777, 0o600)
        registry = json.loads(stage.read_bytes())
        for references, directory, compiler in ((registry.get('tor_exits') or [], tor_sources, 'compile-server-tor-source'),
                                                  (registry.get('node_chains') or [], ordered_sources, 'compile-server-node-chain-source')):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            for reference in references:
                path = directory/(reference['source_sha256']+'.json')
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                raw = path.read_bytes()
                compiled = self.compile(json.loads(raw), compiler)
                if compiled['reference'] != reference or compiled['source_json'].encode() != raw:
                    raise subprocess.CalledProcessError(1, command)
        if INSTALLED:
            # This is the actual fixed-path command from the built image. A
            # source recompile or mocked success cannot replace its native
            # graph and installed-package checks.
            self.real_run([str(self.agent), *command[1:]], **kwargs)
            type(self).native_checks += 1
        elif self.native_checker is not None:
            environment = dict(os.environ, ROUTERVPN_ORDERED_PAIRING_REGISTRY=str(stage), ROUTERVPN_ORDERED_PAIRING_AGENT_CONFIG=command[3],
                               ROUTERVPN_ORDERED_PAIRING_TOR_SOURCES=str(tor_sources), ROUTERVPN_ORDERED_PAIRING_SOURCES=str(ordered_sources),
                               ROUTERVPN_ORDERED_PAIRING_EXPECTED=str(sum(len(registry.get(name) or []) for name in ('exits', 'tor_exits', 'node_chains'))))
            self.real_run([str(self.native_checker), '-test.run=^TestRouterVPNOperatorOrderedStagedRegistry$', '-test.timeout=60s'],
                          env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=70)
            type(self).native_checks += 1
        if self.on_check is not None:
            self.on_check()
        return subprocess.CompletedProcess(command, 0)

    def run_pair(self, extra=(), selection=None):
        selection = ['--node-chain-source', str(self.input)] if selection is None else selection
        argv = ['pair', *selection, '--registry', str(self.registry), '--agent-config', str(self.agent_config), '--listen-ip', '10.77.0.1', *map(str, extra)]
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(PAIR.subprocess, 'run', side_effect=self.execute), contextlib.redirect_stdout(self.output):
            PAIR.main()
        self.assertNotIn('private-preserved-proxy-key', self.output.getvalue())
        self.assertNotIn('captured-chain-token-', self.output.getvalue())

    def assert_saved(self):
        for path, (body, inode) in self.saved.items():
            self.assertEqual((path.read_bytes(), path.stat().st_ino), (body, inode))
        self.assertFalse(list(self.root.glob('.relay-pair-*')))
        self.assertFalse(list(self.sources.glob('.node-chain-source-*')))

    def assert_preserved(self):
        self.assertEqual(self.registry.read_bytes(), self.before)
        self.assert_saved()

    def write_plan(self, name='wg/imported-bootstrap'):
        row = copy.deepcopy(self.plans[name])
        original = row['plan']
        paths = []

        def put(label, value, *, text=False):
            path = self.root/'plan-inputs'/(label+'.json')
            self.write(path, value.encode() if text else json.dumps(value, ensure_ascii=False).encode())
            paths.append(path)
            # Exercise both explicit absolute names and paths relative to the
            # plan file; neither form permits links or implicit node defaults.
            return str(path) if len(paths) % 2 == 0 else str(path.relative_to(self.root))

        def select(value, label, peer=False):
            selection = dict(bundle_file=put(label+'-bundle', value['bundle']), profile_id=value['profile_id'])
            if not peer:
                selection['mode'] = value['mode']
                if 'dns_bootstrap' in value:
                    selection['dns_bootstrap_file'] = put(label+'-bootstrap', value['dns_bootstrap'], text=True)
            return selection

        plan = dict(schema=original['schema'], entry=select(original['entry'], 'entry'), members=[])
        for position, member in enumerate(original['members']):
            if 'imported' in member:
                plan['members'].append({'imported': {'capture_file': put(str(position)+'-imported', member['imported'])}})
            elif 'openvpn' in member:
                value = member['openvpn']
                plan['members'].append({'openvpn': {
                    'local_capture_file': put(str(position)+'-openvpn-local', value['local']),
                    'server_capture_file': put(str(position)+'-openvpn-server', value['server']),
                    'pairing_file': put(str(position)+'-openvpn-pairing', value['pairing'])}})
            else:
                plan['members'].append(dict(paired=select(member['paired'], str(position)+'-client'),
                                            server_peer=select(member['server_peer'], str(position)+'-server', peer=True)))
        path = self.root/'bundle-plan.json'
        self.write(path, json.dumps(plan).encode())
        paths.insert(0, path)
        return path, plan, paths, row

    def test_bundle_plan_compiles_original_selections_and_independent_server_keys(self):
        for name in PLAN_NAMES:
            with self.subTest(name=name):
                path, plan, paths, row = self.write_plan(name)
                originals = {p: (p.read_bytes(), p.stat().st_ino) for p in paths}
                self.run_pair(selection=['--node-chain-plan', str(path)])
                registry = json.loads(self.registry.read_bytes())
                self.assertIn(row['reference'], registry['node_chains'])
                source = self.sources/(row['reference']['source_sha256']+'.json')
                self.assertEqual(source.read_bytes(), row['source_json'].encode())
                self.assertEqual(source.stat().st_mode & 0o777, 0o600)
                inode = source.stat().st_ino
                self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assertEqual(source.stat().st_ino, inode)
                for p, observed in originals.items():
                    self.assertEqual((p.read_bytes(), p.stat().st_ino), observed)
                self.assert_saved()
        self.assertEqual(self.checks, 2*len(PLAN_NAMES))

    def test_bundle_plan_refuses_borrowed_server_keys_and_wrong_original_identity(self):
        for fault in ('client-key', 'wrong-node', 'implicit-profile', 'missing-peer', 'unrequested-entry'):
            with self.subTest(fault=fault):
                path, plan, paths, row = self.write_plan('awg2-strong/paired')
                final = plan['members'][-1]
                if fault == 'client-key':
                    final['server_peer'] = dict(bundle_file=final['paired']['bundle_file'], profile_id=final['paired']['profile_id'])
                elif fault == 'wrong-node':
                    peer = self.root/final['server_peer']['bundle_file']
                    bundle = json.loads(peer.read_bytes())
                    bundle['routerProfiles'][0]['node_proof_id'] = 'f'*64
                    self.write(peer, json.dumps(bundle).encode())
                elif fault == 'implicit-profile':
                    final['paired'].pop('profile_id')
                elif fault == 'missing-peer':
                    final.pop('server_peer')
                else:
                    plan['entry_node_id'] = self.node
                self.write(path, json.dumps(plan).encode())
                with self.assertRaises(ValueError):
                    self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_bundle_plan_requires_exact_private_files_and_original_imported_strings(self):
        for fault in ('symlink', 'hardlink', 'public-mode', 'duplicate-json', 'extra-capture', 'object-capture', 'url', 'boolean-schema'):
            with self.subTest(fault=fault):
                path, plan, paths, row = self.write_plan()
                imported = self.root/plan['members'][0]['imported']['capture_file']
                raw = imported.read_bytes()
                backup = self.root/'original-imported.json'
                if backup.exists():
                    backup.unlink()
                if fault == 'symlink':
                    imported.rename(backup)
                    imported.symlink_to(backup)
                elif fault == 'hardlink':
                    os.link(imported, backup)
                elif fault == 'public-mode':
                    imported.chmod(0o644)
                elif fault == 'duplicate-json':
                    self.write(imported, raw[:-1]+b',"config":"duplicate-private-source"}')
                elif fault in ('extra-capture', 'object-capture'):
                    value = json.loads(raw)
                    if fault == 'extra-capture':
                        value['private'] = 'unexpected'
                    else:
                        value['capture'] = json.loads(value['capture'])
                    self.write(imported, json.dumps(value).encode())
                elif fault == 'url':
                    plan['members'][0]['imported']['capture_file'] = 'https://example.invalid/private.json'
                else:
                    plan['schema'] = True
                self.write(path, json.dumps(plan).encode())
                try:
                    with self.assertRaises(ValueError):
                        self.run_pair(selection=['--node-chain-plan', str(path)])
                    self.assert_preserved()
                finally:
                    if imported.is_symlink():
                        imported.unlink()
                    if backup.exists():
                        backup.unlink()
                    if imported.exists():
                        imported.chmod(0o600)
        self.assertEqual(self.checks, 0)

    def test_bundle_plan_rechecks_every_original_inode_after_native_validation(self):
        initial, plan, paths, row = self.write_plan()
        for target in paths:
            with self.subTest(input=target.name):
                path, plan, current_paths, row = self.write_plan()
                replaced = []
                def change():
                    before = target.stat().st_ino
                    self.write(target, target.read_bytes())
                    self.assertNotEqual(target.stat().st_ino, before)
                    replaced.append(target.stat().st_ino)
                self.on_check = change
                with self.assertRaisesRegex(ValueError, 'changed during native validation'):
                    self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assertEqual(target.stat().st_ino, replaced[0])
                self.assert_preserved()
                self.assertFalse((self.sources/(row['reference']['source_sha256']+'.json')).exists())
        self.assertEqual(self.checks, len(paths))

    def test_bundle_plan_dry_run_cannot_replace_any_referenced_input(self):
        path, plan, paths, row = self.write_plan()
        originals = {p: (p.read_bytes(), p.stat().st_ino) for p in paths}
        for target in paths:
            with self.subTest(input=target.name), self.assertRaises(ValueError):
                self.run_pair(['--dry-run', target], selection=['--node-chain-plan', str(path)])
        for p, value in originals.items():
            self.assertEqual((p.read_bytes(), p.stat().st_ino), value)
        review = self.root/'plan-review'/'review.json'
        self.run_pair(['--dry-run', review], selection=['--node-chain-plan', str(path)])
        value = json.loads(review.read_bytes())
        self.assertIn(row['reference'], value['registry']['node_chains'])
        self.assertEqual(value['node_chain_sources'][row['reference']['source_sha256']], row['source_json'])
        self.assertEqual(self.checks, 1)
        self.assert_preserved()

    def test_bundle_plan_keeps_alias_and_bundle_option_rejections(self):
        path, plan, paths, row = self.write_plan()
        for arguments in (['--exit-id', 'alias'], ['--bundle', str(self.input)], ['--node-chain-source', str(self.input)]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.run_pair(arguments, selection=['--node-chain-plan', str(path)])
        for arguments in (['--bundle-profile', 'other'], ['--server-peer-profile', str(self.input)]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.run_pair(arguments, selection=['--node-chain-plan', str(path)])
        self.assertEqual(self.checks, 0)
        self.assert_preserved()

    def test_bundle_plan_bounds_private_input_and_suppresses_compiler_payload(self):
        path, plan, paths, row = self.write_plan()
        bound = sum(p.stat().st_size for p in paths)-1
        with mock.patch.object(PAIR, 'MAX_NODE_CHAIN_SOURCE_BYTES', bound), mock.patch.object(PAIR.subprocess, 'run') as command, self.assertRaises(ValueError):
            PAIR.compile_node_chain_plan(path, self.node)
        command.assert_not_called()
        for failure in (OSError('private-secret'), subprocess.CalledProcessError(1, []), subprocess.TimeoutExpired([], 20)):
            with mock.patch.object(PAIR.subprocess, 'run', side_effect=failure), self.assertRaises(ValueError) as result:
                PAIR.compile_node_chain_plan(path, self.node)
            self.assertNotIn('private-secret', str(result.exception))
        for output in (b'', b'{}', b'{"source_json":"private-secret","reference":{}}'):
            with mock.patch.object(PAIR.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')), self.assertRaises(ValueError) as result:
                PAIR.compile_node_chain_plan(path, self.node)
            self.assertNotIn('private-secret', str(result.exception))
        self.assert_preserved()

    def test_source_digest_matches_actual_go_domains_and_string_encoding(self):
        self.assertEqual(len(self.digest_vectors), 24)
        for vector in self.digest_vectors:
            with self.subTest(schema=vector['schema'], text_length=len(vector['text'])):
                self.assertEqual(PAIR.node_chain_source_digest(vector['text'], vector['schema']), vector['digest'])

    def test_socks_prefix_source_and_plan_keep_actual_typed_compiler(self):
        for name in SOCKS_NAMES:
            with self.subTest(name=name, form='source'):
                row = self.fixtures[name]
                self.write(self.input, json.dumps(row['source']).encode())
                self.run_pair()
                self.assertEqual((self.sources/(row['reference']['source_sha256']+'.json')).read_bytes(), row['source_json'].encode())
                self.assert_saved()
            with self.subTest(name=name, form='plan'):
                path, plan, paths, row = self.write_plan(name)
                original = {p: (p.read_bytes(), p.stat().st_ino) for p in paths}
                self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assertEqual((self.sources/(row['reference']['source_sha256']+'.json')).read_bytes(), row['source_json'].encode())
                for p, value in original.items():
                    self.assertEqual((p.read_bytes(), p.stat().st_ino), value)
        self.assertEqual(self.checks, 12)

    def test_socks_prefix_original_authority_and_private_snapshot_refusals(self):
        for name in SOCKS_NAMES:
            for fault in ('schema1', 'schema2', 'schema4', 'fake-packet', 'borrowed-key'):
                with self.subTest(name=name, fault=fault):
                    if fault == 'borrowed-key':
                        path, plan, paths, row = self.write_plan(name)
                        paired = plan['members'][-1]
                        paired['server_peer'] = dict(bundle_file=paired['paired']['bundle_file'], profile_id=paired['paired']['profile_id'])
                        self.write(path, json.dumps(plan).encode())
                        selection = ['--node-chain-plan', str(path)]
                    else:
                        source = copy.deepcopy(self.fixtures[name]['source'])
                        if fault.startswith('schema'):
                            source['schema'] = int(fault[-1])
                        else:
                            source['identity_sources'][-2] = source['identity_sources'][-1]
                        self.write(self.input, json.dumps(source).encode())
                        selection = None
                    with self.assertRaises(ValueError):
                        self.run_pair(selection=selection)
                    self.assert_preserved()
        self.assertEqual(self.checks, 0)
        path, _, paths, _ = self.write_plan(SOCKS_NAMES[-1])
        target = paths[-1]
        def replace():
            inode = target.stat().st_ino
            self.write(target, target.read_bytes())
            self.assertNotEqual(target.stat().st_ino, inode)
        self.on_check = replace
        with self.assertRaisesRegex(ValueError, 'changed during native validation'):
            self.run_pair(selection=['--node-chain-plan', str(path)])
        self.assert_preserved()

    def test_connect_source_family_and_original_authority_cannot_be_substituted(self):
        for name in CONNECT_NAMES:
            for fault in ('schema1', 'schema2', 'schema3', 'schema5', 'boolean-schema', 'ss-middle', 'fake-packet', 'changed-final'):
                with self.subTest(name=name, fault=fault):
                    source = copy.deepcopy(self.fixtures[name]['source'])
                    if fault.startswith('schema'):
                        source['schema'] = int(fault[-1])
                    elif fault == 'boolean-schema':
                        source['schema'] = True
                    elif fault == 'ss-middle':
                        source['nodes'][-2] = self.fixtures['wg/']['source']['nodes'][0]
                    elif fault == 'fake-packet':
                        source['identity_sources'][-2] = source['identity_sources'][-1]
                    else:
                        source['nodes'][-1] = source['nodes'][-2]
                    self.write(self.input, json.dumps(source).encode())
                    with self.assertRaises(ValueError):
                        self.run_pair()
                    self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_connect_plan_keeps_distinct_server_key_and_original_private_inodes(self):
        for name in CONNECT_NAMES:
            with self.subTest(name=name, fault='borrowed-key'):
                path, plan, paths, row = self.write_plan(name)
                paired = plan['members'][-1]
                paired['server_peer'] = dict(bundle_file=paired['paired']['bundle_file'], profile_id=paired['paired']['profile_id'])
                self.write(path, json.dumps(plan).encode())
                with self.assertRaises(ValueError):
                    self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assert_preserved()
        self.assertEqual(self.checks, 0)
        name = 'connect/awg2-strong/https-connect'
        _, _, originals, _ = self.write_plan(name)
        for target in originals:
            with self.subTest(input=target.name, fault='replaced-inode'):
                path, _, _, row = self.write_plan(name)
                def replace():
                    inode = target.stat().st_ino
                    self.write(target, target.read_bytes())
                    self.assertNotEqual(target.stat().st_ino, inode)
                self.on_check = replace
                with self.assertRaisesRegex(ValueError, 'changed during native validation'):
                    self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assert_preserved()
                self.assertFalse((self.sources/(row['reference']['source_sha256']+'.json')).exists())
        self.assertEqual(self.checks, len(originals))

    def test_ordered_only_registry_retains_empty_tor_position_and_absent_legacy_lists(self):
        for empty in ({}, {'exits': None, 'tor_exits': None, 'node_chains': None}):
            value = dict(listen_ip='10.77.0.1', first_port=26240, last_port=26271, ttl_seconds=90, **empty)
            self.write(self.registry, PAIR.registry_bytes(value))
            self.run_pair()
            saved = json.loads(self.registry.read_bytes())
            self.assertEqual(saved['node_chains'], [self.selected['reference']])
            self.assertIsNone(saved.get('exits'))
            self.assertIsNone(saved.get('tor_exits'))
            self.assert_saved()

    def test_openvpn_original_independent_roles_and_source_publish_privately(self):
        for name in OPENVPN_NAMES:
            with self.subTest(name=name):
                row = self.fixtures[name]
                self.write(self.input, json.dumps(row['source']).encode())
                self.run_pair()
                reference = row['reference']
                self.assertIn(reference, json.loads(self.registry.read_bytes())['node_chains'])
                self.assertEqual((self.sources/(reference['source_sha256']+'.json')).read_bytes(), row['source_json'].encode())
                self.assertEqual(reference['schema'], 5)
                middle = reference['members'][-2]
                self.assertRegex(middle['openvpn_pair_sha256'], r'^[0-9a-f]{64}$')
                self.assertNotIn('original-server-provider', json.dumps(reference))
                self.assertNotIn('private_key', json.dumps(reference))

    def test_multiple_imported_source_keeps_all_original_positions(self):
        for name in MULTIPLE_IMPORTED_NAMES:
            with self.subTest(name=name):
                row = self.fixtures[name]
                self.write(self.input, json.dumps(row['source']).encode())
                self.run_pair()
                reference = row['reference']
                self.assertEqual(reference['schema'], 6)
                self.assertIn(reference, json.loads(self.registry.read_bytes())['node_chains'])
                self.assertEqual((self.sources/(reference['source_sha256']+'.json')).read_bytes(), row['source_json'].encode())
                imports = [member for member in reference['members'] if member.get('node_kind') == 'external']
                self.assertGreaterEqual(len(imports), 2)
                self.assertEqual(len({member['source_sha256'] for member in imports}), len(imports))
                for member in imports:
                    self.assertEqual(member['proof_kind'], 'public-path')
                    self.assertEqual(member['node_id'], '')
                    self.assertNotIn('client_public_key', member)
                    self.assertNotIn('server_public_key', member)
                    self.assertEqual(row['source']['identity_sources'][member['position']-1], '')
                self.assert_saved()

    def test_multiple_imported_private_plan_refuses_substitution(self):
        for fault in ('schema1', 'schema3', 'schema4', 'schema5', 'boolean-schema',
                      'duplicate-import', 'import-final', 'missing-final-peer',
                      'changed-private-capture', 'public-mode', 'equal-byte-first', 'equal-byte-second'):
            with self.subTest(fault=fault):
                path, plan, paths, row = self.write_plan('multiple/wg/adjacent')
                first, second = plan['members'][0]['imported'], plan['members'][1]['imported']
                imported_path = self.root/second['capture_file']
                self.on_check = None
                if fault.startswith('schema'):
                    plan['schema'] = int(fault[-1])
                elif fault == 'boolean-schema':
                    plan['schema'] = True
                elif fault == 'duplicate-import':
                    second['capture_file'] = first['capture_file']
                elif fault == 'import-final':
                    plan['members'][-1] = copy.deepcopy(plan['members'][1])
                elif fault == 'missing-final-peer':
                    plan['members'][-1].pop('server_peer')
                elif fault == 'changed-private-capture':
                    value = json.loads(imported_path.read_bytes())
                    value['capture'] = json.loads((self.root/first['capture_file']).read_bytes())['capture']
                    self.write(imported_path, json.dumps(value).encode())
                elif fault == 'public-mode':
                    imported_path.chmod(0o644)
                self.write(path, json.dumps(plan).encode())
                if fault.startswith('equal-byte-'):
                    target = self.root/(first if fault.endswith('first') else second)['capture_file']
                    def replace():
                        inode = target.stat().st_ino
                        self.write(target, target.read_bytes())
                        self.assertNotEqual(target.stat().st_ino, inode)
                    self.on_check = replace
                    with self.assertRaisesRegex(ValueError, 'changed during native validation'):
                        self.run_pair(selection=['--node-chain-plan', str(path)])
                else:
                    with self.assertRaises(ValueError):
                        self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assertFalse((self.sources/(row['reference']['source_sha256']+'.json')).exists())
                self.assert_preserved()

    def test_openvpn_private_pair_and_original_capture_refusals(self):
        for fault in ('missing-pair', 'same-provider', 'schema', 'borrowed-role', 'private-local-key', 'public-mode', 'equal-byte-replacement'):
            with self.subTest(fault=fault):
                path, plan, paths, row = self.write_plan('openvpn/wg/tcp')
                member = plan['members'][-2]['openvpn']
                pair_path = self.root/member['pairing_file']
                pair = json.loads(pair_path.read_bytes())
                if fault == 'missing-pair':
                    member.pop('pairing_file')
                elif fault == 'same-provider':
                    pair['local'] = pair['server']
                    self.write(pair_path, json.dumps(pair).encode())
                elif fault == 'schema':
                    plan['schema'] = 4
                elif fault == 'borrowed-role':
                    member['server_capture_file'] = member['local_capture_file']
                elif fault == 'private-local-key':
                    pair['private_local_key'] = 'unowned-secret'
                    self.write(pair_path, json.dumps(pair).encode())
                elif fault == 'public-mode':
                    pair_path.chmod(0o644)
                self.write(path, json.dumps(plan).encode())
                if fault == 'equal-byte-replacement':
                    def replace():
                        inode = pair_path.stat().st_ino
                        self.write(pair_path, pair_path.read_bytes())
                        self.assertNotEqual(pair_path.stat().st_ino, inode)
                    self.on_check = replace
                    with self.assertRaisesRegex(ValueError, 'changed during native validation'):
                        self.run_pair(selection=['--node-chain-plan', str(path)])
                else:
                    with self.assertRaises(ValueError):
                        self.run_pair(selection=['--node-chain-plan', str(path)])
                self.assert_preserved()

    def test_actual_schema2_descriptor_publishes_privately_and_is_idempotent(self):
        self.run_pair()
        registry = json.loads(self.registry.read_bytes())
        self.assertEqual(registry['exits'], self.original['exits'])
        self.assertEqual(registry['tor_exits'], self.original['tor_exits'])
        self.assertEqual(registry['node_chains'], [self.previous['reference'], self.selected['reference']])
        path = self.sources/(self.selected['reference']['source_sha256']+'.json')
        self.assertEqual(path.read_bytes(), self.selected['source_json'].encode())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.stat().st_nlink, 1)
        inode = path.stat().st_ino
        self.run_pair()
        self.assertEqual(path.stat().st_ino, inode)
        self.assertEqual(json.loads(self.registry.read_bytes())['node_chains'], registry['node_chains'])
        self.assertEqual(self.checks, 2)
        self.assert_saved()

    def test_all_three_bases_layers_and_selected_dns_keep_distinct_sources(self):
        retained = {}
        for name, row in self.fixtures.items():
            with self.subTest(name=name):
                self.write(self.input, json.dumps(row['source']).encode())
                self.run_pair()
                path = self.sources/(row['reference']['source_sha256']+'.json')
                self.assertEqual(path.read_bytes(), row['source_json'].encode())
                retained[path] = path.read_bytes(), path.stat().st_ino
                for previous, value in retained.items():
                    self.assertEqual((previous.read_bytes(), previous.stat().st_ino), value)
        registry = json.loads(self.registry.read_bytes())
        self.assertEqual(len(registry['node_chains']), len(self.fixtures))
        self.assertNotEqual(self.fixtures['wg/']['reference']['dns_policy_sha256'], self.fixtures['wg/custom-dns']['reference']['dns_policy_sha256'])
        self.assertEqual(registry['exits'], self.original['exits'])
        self.assertEqual(registry['tor_exits'], self.original['tor_exits'])
        self.assert_saved()

    def test_dry_run_contains_all_original_sources_without_live_writes(self):
        review = self.root/'review'/'plan.json'
        self.run_pair(['--dry-run', review])
        self.assert_preserved()
        self.assertFalse((self.root/'.registry.json.lock').exists())
        self.assertEqual(review.stat().st_mode & 0o777, 0o600)
        plan = json.loads(review.read_bytes())
        self.assertEqual(plan['entry_node_id'], self.node)
        for reference in plan['registry']['node_chains']:
            raw = plan['node_chain_sources'][reference['source_sha256']]
            self.assertEqual(self.compile(json.loads(raw))['reference'], reference)
        self.assertEqual(plan['tor_sources'], {self.tor['reference']['source_sha256']: self.tor['source_json']})
        self.assertFalse((self.sources/(self.selected['reference']['source_sha256']+'.json')).exists())

    def test_legacy_tor_and_bundle_transactions_validate_every_existing_ordered_source(self):
        tor_input, bundle = self.root/'tor-input.json', self.root/'bundle.json'
        tor = dict(schema=1, id='new-tor', entry_node_id=self.node, mode='tor', dns=dict(mode='home'), adguard_ipv4='192.168.50.133')
        self.write(tor_input, json.dumps(tor).encode())
        outbound = dict(type='shadowsocks', tag='proxy', server='198.51.100.2', server_port=8388, method='aes-256-gcm', password='private-new-proxy-key')
        value = dict(selectedRouterID='ordinary', routerProfiles=[dict(id='ordinary', node_kind='router-vpn', endpoint='198.51.100.2',
                     adguard_ipv4='10.88.0.1', node_proof_id='c'*64)],
                     profiles={'shadowsocks': {'sing-box.json': base64.b64encode(json.dumps(dict(outbounds=[outbound])).encode()).decode()}})
        self.write(bundle, json.dumps(value).encode())
        for selection in (['--tor-source', str(tor_input), '--exit-id', 'new-tor'], ['--bundle', str(bundle), '--exit-id', 'new-ordinary']):
            with self.subTest(selection=selection[0]):
                self.run_pair(selection=selection)
                self.assertEqual(json.loads(self.registry.read_bytes())['node_chains'], self.original['node_chains'])
                self.assert_saved()
        self.assertEqual(self.checks, 2)

    def test_legacy_write_refuses_stale_or_missing_ordered_source(self):
        tor_input = self.root/'tor-input.json'
        self.write(tor_input, json.dumps(dict(schema=1, id='new-tor', entry_node_id=self.node, mode='tor', dns=dict(mode='home'), adguard_ipv4='192.168.50.133')).encode())
        selection = ['--tor-source', str(tor_input), '--exit-id', 'new-tor']
        self.on_check = lambda: self.write(self.previous_path, self.previous_path.read_bytes())
        with self.assertRaisesRegex(ValueError, 'changed'):
            self.run_pair(selection=selection)
        self.assertEqual(self.registry.read_bytes(), self.before)
        self.previous_path.unlink()
        self.on_check = None
        with self.assertRaises(FileNotFoundError):
            self.run_pair(selection=selection)
        self.assertEqual(self.registry.read_bytes(), self.before)

    def test_all_three_registry_families_share_the_64_source_bound(self):
        value = copy.deepcopy(self.original)
        value['node_chains'] *= 63
        self.write(self.registry, PAIR.registry_bytes(value))
        before = self.registry.read_bytes()
        with self.assertRaisesRegex(ValueError, 'count exceeds bound'):
            self.run_pair()
        self.assertEqual(self.registry.read_bytes(), before)
        self.assertEqual(self.checks, 0)

    def test_no_alias_is_required_or_accepted_for_ordered_descriptors(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            self.run_pair(['--exit-id', 'invented-alias'])
        self.assertEqual(failure.exception.code, 2)
        for selection in (['--tor-source', str(self.input)], ['--bundle', str(self.input)]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                self.run_pair(selection=selection)
            self.assertEqual(failure.exception.code, 2)
        self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_bundle_only_options_and_overlapping_review_targets_are_refused(self):
        for extra in (['--bundle-profile', 'borrowed'], ['--server-peer-profile', self.input],
                      *[['--dry-run', p] for p in (self.input, self.registry, self.agent_config, self.sources/'plan.json', self.tor_sources/'plan.json')]):
            with self.subTest(extra=str(extra)), self.assertRaises(ValueError):
                self.run_pair(extra)
        self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_compiler_rejects_changed_entry_or_original_private_authority(self):
        for fault in ('entry', 'schema', 'identity', 'nodes', 'extra'):
            source = copy.deepcopy(self.selected['source'])
            if fault == 'entry': source['entry_node_id'] = 'e'*64
            if fault == 'schema': source['schema'] = 1
            if fault == 'identity': source['identity_sources'][-2] = source['identity_sources'][-1]
            if fault == 'nodes': source['nodes'].reverse()
            if fault == 'extra': source['private-secret-must-not-echo'] = 'malformed'
            self.write(self.input, json.dumps(source).encode())
            with self.subTest(fault=fault), self.assertRaises(ValueError) as failure:
                self.run_pair()
            self.assertNotIn('private-secret-must-not-echo', str(failure.exception))
            self.assert_preserved()
        self.assertEqual(self.checks, 0)

    def test_returned_descriptor_and_source_cannot_be_substituted(self):
        def change_source(value):
            source = json.loads(value['source_json'])
            source['entry_id'] = 'borrowed-entry'
            value['source_json'] = json.dumps(source)
        changes = (
            change_source,
            lambda value: value['reference'].update(entry_node_id='e'*64),
            lambda value: value['reference'].update(source_sha256='e'*64),
            lambda value: value['reference'].update(schema=1),
            lambda value: value['reference']['members'][0].update(position=2),
            lambda value: value['reference'].update(private_secret='must-not-echo'),
        )
        for change in changes:
            self.compiler_change = change
            with self.subTest(change=changes.index(change)), self.assertRaises(ValueError):
                self.run_pair()
            self.assert_preserved()
        # An equally shaped but wrong selected-DNS descriptor must fail the
        # actual compiled-source comparison in the staged checker as well.
        self.compiler_change = lambda value: value['reference'].update(dns_policy_sha256='e'*64)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_pair()
        self.assert_preserved()

    def test_duplicate_or_conflicting_digest_does_not_replace_saved_descriptor(self):
        for duplicate in (False, True):
            value = copy.deepcopy(self.original)
            reference = copy.deepcopy(self.selected['reference'])
            if duplicate:
                value['node_chains'] += [reference, copy.deepcopy(reference)]
            else:
                reference['dns_policy_sha256'] = 'e'*64
                value['node_chains'].append(reference)
            self.write(self.registry, PAIR.registry_bytes(value))
            before = self.registry.read_bytes()
            with self.assertRaisesRegex(ValueError, 'descriptor differs'):
                self.run_pair()
            self.assertEqual(self.registry.read_bytes(), before)
        self.assertEqual(self.checks, 0)

    def test_input_existing_sources_and_directories_require_private_owned_inodes(self):
        for fault in ('input-public', 'source-public', 'source-link', 'parent-link', 'directory-public'):
            with self.subTest(fault=fault):
                if fault == 'input-public': self.input.chmod(0o644)
                if fault == 'source-public': self.previous_path.chmod(0o644)
                if fault == 'source-link':
                    self.previous_path.rename(self.previous_path.with_suffix('.owned'))
                    self.previous_path.symlink_to(self.previous_path.with_suffix('.owned'))
                if fault == 'parent-link':
                    self.sources.rename(self.root/'owned-sources')
                    self.sources.symlink_to(self.root/'owned-sources', target_is_directory=True)
                if fault == 'directory-public': self.sources.chmod(0o755)
                with self.assertRaises((ValueError, RuntimeError, OSError)):
                    self.run_pair()
                self.assertEqual(self.registry.read_bytes(), self.before)
                if fault == 'input-public': self.input.chmod(0o600)
                if fault == 'source-public': self.previous_path.chmod(0o600)
                if fault == 'source-link':
                    self.previous_path.unlink()
                    self.previous_path.with_suffix('.owned').rename(self.previous_path)
                if fault == 'parent-link':
                    self.sources.unlink()
                    (self.root/'owned-sources').rename(self.sources)
                if fault == 'directory-public': self.sources.chmod(0o700)
        self.assertEqual(self.checks, 0)

    def test_equal_byte_replacement_or_checker_refusal_cannot_publish(self):
        for path in (self.input, self.agent_config, self.previous_path, self.tor_path, self.registry):
            self.on_check = lambda path=path: self.write(path, path.read_bytes())
            with self.subTest(path=path.name), self.assertRaisesRegex(ValueError, 'changed'):
                self.run_pair()
            self.assertEqual(self.registry.read_bytes(), self.before)
        self.on_check = lambda: (_ for _ in ()).throw(RuntimeError('native rejection sentinel'))
        with self.assertRaisesRegex(RuntimeError, 'native rejection'):
            self.run_pair()
        self.assertFalse((self.sources/(self.selected['reference']['source_sha256']+'.json')).exists())

    def test_replaced_directory_or_existing_hash_collision_is_preserved(self):
        target = self.sources/(self.selected['reference']['source_sha256']+'.json')
        self.write(target, b'{"foreign":"preserve"}')
        with self.assertRaisesRegex(ValueError, 'immutable ordered source'):
            self.run_pair()
        self.assertEqual(target.read_bytes(), b'{"foreign":"preserve"}')
        self.assert_preserved()
        target.unlink()
        def replace():
            self.sources.rename(self.root/'previous-sources')
            self.sources.mkdir(mode=0o700)
            self.write(self.sources/'replacement.json', b'{"owner":"preserve"}')
        self.on_check = replace
        with self.assertRaisesRegex((ValueError, FileNotFoundError), 'changed|No such file'):
            self.run_pair()
        self.assertEqual(self.registry.read_bytes(), self.before)
        self.assertEqual((self.sources/'replacement.json').read_bytes(), b'{"owner":"preserve"}')

    def failure_writer(self, callback):
        original = PAIR.helpers
        def helpers():
            read, write, parent = original()
            def guarded(path, body):
                if Path(path) == self.registry:
                    callback(write, body)
                else:
                    write(path, body)
            return read, guarded, parent
        return mock.patch.object(PAIR, 'helpers', side_effect=helpers)

    def test_failed_publication_removes_only_the_new_owned_source(self):
        def fail(write, body): raise RuntimeError('registry rejected')
        with self.failure_writer(fail), self.assertRaisesRegex(RuntimeError, 'registry rejected'):
            self.run_pair()
        self.assert_preserved()
        self.assertFalse((self.sources/(self.selected['reference']['source_sha256']+'.json')).exists())

    def test_post_commit_failure_preserves_the_now_referenced_source(self):
        def fail(write, body):
            write(self.registry, body)
            raise RuntimeError('post-commit rejected')
        with self.failure_writer(fail), self.assertRaisesRegex(RuntimeError, 'post-commit'):
            self.run_pair()
        reference = json.loads(self.registry.read_bytes())['node_chains'][-1]
        self.assertEqual(reference, self.selected['reference'])
        self.assertEqual((self.sources/(reference['source_sha256']+'.json')).read_bytes(), self.selected['source_json'].encode())
        self.assert_saved()

    def test_failed_write_or_adoption_race_preserves_a_replacement_owner(self):
        target = self.sources/(self.selected['reference']['source_sha256']+'.json')
        def fail(write, body):
            write(target, b'{"replacement":"preserve"}')
            raise RuntimeError('registry rejected after replacement')
        with self.failure_writer(fail), self.assertRaisesRegex(RuntimeError, 'after replacement'):
            self.run_pair()
        self.assertEqual(target.read_bytes(), b'{"replacement":"preserve"}')
        self.assert_preserved()
        target.unlink()
        link = os.link
        def replace(source, destination, **kwargs):
            self.write(destination, b'{"new-owner":"preserve"}')
            return link(source, destination, **kwargs)
        with mock.patch.object(PAIR.os, 'link', side_effect=replace), self.assertRaises(FileExistsError):
            self.run_pair()
        self.assertEqual(target.read_bytes(), b'{"new-owner":"preserve"}')
        self.assert_preserved()

    def test_bounded_compiler_and_private_errors_do_not_return_imported_text(self):
        source = json.dumps(self.selected['source']).encode()
        for output in (b'', b'{}', b'{"source_json":"private-secret","reference":{}}'):
            with mock.patch.object(PAIR.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, output, b'')), self.assertRaises(ValueError) as failure:
                PAIR.compile_node_chain_source(source, self.node)
            self.assertNotIn('private-secret', str(failure.exception))
        for failure in (OSError('private-secret'), subprocess.CalledProcessError(1, []), subprocess.TimeoutExpired([], 20)):
            with mock.patch.object(PAIR.subprocess, 'run', side_effect=failure), self.assertRaises(ValueError) as result:
                PAIR.compile_node_chain_source(source, self.node)
            self.assertNotIn('private-secret', str(result.exception))
        with mock.patch.object(PAIR, 'MAX_NODE_CHAIN_SOURCE_BYTES', len(source)-1), mock.patch.object(PAIR.subprocess, 'run') as command, self.assertRaises(ValueError):
            PAIR.compile_node_chain_source(source, self.node)
        command.assert_not_called()
        with mock.patch.object(PAIR, 'MAX_NODE_CHAIN_SOURCE_BYTES', len(source)), mock.patch.object(PAIR.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'x'*(2*len(source)+4097), b'')), self.assertRaises(ValueError):
            PAIR.compile_node_chain_source(source, self.node)
        self.assert_preserved()


TEST_NAMES = (
    'test_actual_schema2_descriptor_publishes_privately_and_is_idempotent',
    'test_all_three_bases_layers_and_selected_dns_keep_distinct_sources',
    'test_all_three_registry_families_share_the_64_source_bound',
    'test_bounded_compiler_and_private_errors_do_not_return_imported_text',
    'test_bundle_only_options_and_overlapping_review_targets_are_refused',
    'test_bundle_plan_bounds_private_input_and_suppresses_compiler_payload',
    'test_bundle_plan_compiles_original_selections_and_independent_server_keys',
    'test_bundle_plan_dry_run_cannot_replace_any_referenced_input',
    'test_bundle_plan_keeps_alias_and_bundle_option_rejections',
    'test_bundle_plan_rechecks_every_original_inode_after_native_validation',
    'test_bundle_plan_refuses_borrowed_server_keys_and_wrong_original_identity',
    'test_bundle_plan_requires_exact_private_files_and_original_imported_strings',
    'test_compiler_rejects_changed_entry_or_original_private_authority',
    'test_connect_plan_keeps_distinct_server_key_and_original_private_inodes',
    'test_connect_source_family_and_original_authority_cannot_be_substituted',
    'test_dry_run_contains_all_original_sources_without_live_writes',
    'test_duplicate_or_conflicting_digest_does_not_replace_saved_descriptor',
    'test_equal_byte_replacement_or_checker_refusal_cannot_publish',
    'test_failed_publication_removes_only_the_new_owned_source',
    'test_failed_write_or_adoption_race_preserves_a_replacement_owner',
    'test_input_existing_sources_and_directories_require_private_owned_inodes',
    'test_legacy_tor_and_bundle_transactions_validate_every_existing_ordered_source',
    'test_legacy_write_refuses_stale_or_missing_ordered_source',
    'test_multiple_imported_private_plan_refuses_substitution',
    'test_multiple_imported_source_keeps_all_original_positions',
    'test_no_alias_is_required_or_accepted_for_ordered_descriptors',
    'test_openvpn_original_independent_roles_and_source_publish_privately',
    'test_openvpn_private_pair_and_original_capture_refusals',
    'test_ordered_only_registry_retains_empty_tor_position_and_absent_legacy_lists',
    'test_post_commit_failure_preserves_the_now_referenced_source',
    'test_replaced_directory_or_existing_hash_collision_is_preserved',
    'test_returned_descriptor_and_source_cannot_be_substituted',
    'test_socks_prefix_original_authority_and_private_snapshot_refusals',
    'test_socks_prefix_source_and_plan_keep_actual_typed_compiler',
    'test_source_digest_matches_actual_go_domains_and_string_encoding',
)


if __name__ == '__main__':
    if OPTIONS.generate_fixtures is not None:
        if remaining_arguments:
            argument_parser.error('host fixture generation does not accept test filters')
        generated = generate_fixtures(OPTIONS.generate_fixtures)
        print(json.dumps({'kind': generated['kind'], 'source_sha': generated['source_sha'], 'source_clean': generated['source_clean'],
                          'source_fixtures': len(generated['rows']), 'digest_vectors': len(generated['digests']), 'bundle_plans': len(generated['plans']),
                          'fixture_sha256': file_identity(OPTIONS.generate_fixtures.absolute())['sha256']}, sort_keys=True))
    else:
        if tuple(unittest.defaultTestLoader.getTestCaseNames(ServerNodeChainPairing)) != TEST_NAMES:
            raise SystemExit('original ordered pairing test inventory changed')
        result = unittest.main(exit=False).result
        if not result.wasSuccessful() or result.testsRun != 35 or result.skipped:
            raise SystemExit('ordered pairing acceptance requires all 27 original, two CONNECT, two SOCKS, two OpenVPN and two multiple-import tests with no skips')
        print(json.dumps({'kind': 'routervpn-private-ordered-pairing-verdict', 'tests': result.testsRun,
                          'source_fixtures': len(FIXTURE_NAMES), 'digest_vectors': 24, 'bundle_plans': len(PLAN_NAMES),
                          'native_checks': ServerNodeChainPairing.native_checks,
                          'scope': 'installed-pairer-and-native-checker' if INSTALLED else ('actual-local-native-checker' if ServerNodeChainPairing.native_checker else 'actual-compiler-and-filesystem'),
                          'source_sha': os.environ.get('ROUTERVPN_ORDERED_PAIRING_SOURCE_SHA') if INSTALLED else None}, sort_keys=True))
