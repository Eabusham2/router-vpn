#!/usr/bin/env python3
"""Execute the actual Darwin fixture alias owner with explicit OS adapters.

Interface inventory and ifconfig are modeled; original ownership, attempted
mutation, join, cleanup and context-aware locking bodies are compiled verbatim.
This is portable source evidence, never native Darwin alias/kernel acceptance.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
HELPER = 'cmd/client/desktop_imported_execution_alias_darwin_test.go'
LOCK = 'internal/desktopnetwork/desktop_network_lock.go'
LEAVES = (
    'owned-close-idempotent', 'unrelated-duplicate-ipv6', 'collision-before-any-mutation',
    'partial-add-error-retains-intent', 'absent-attempted-mutation', 'mask', 'address-index',
    'loopback-index', 'failed-join-retains-original-owner', 'partial-cleanup-retry',
    'nil-join-refused', 'cancelled-cleanup-retains-owner',
)
VERDICTS = ('TestActualAliasOwner', 'TestActualAliasCancelledWaiter') + tuple('TestActualAliasOwner/' + name for name in LEAVES)
ADAPTER = r'''package main
import("context";"errors";"net";"net/netip";"testing";"time";"sync")
type aliasInterface struct { Index int; Flags net.Flags }
var inventory map[netip.Addr]macOSImportedExecutionAliasState
var extraAddresses map[int][]net.Addr
var loopIndex int
var commands [][]string
var commandFault func([]string) (bool,error)
func aliasInterfaceByName(name string)(aliasInterface,error){if name!="lo0"{return aliasInterface{},errors.New("wrong interface")};return aliasInterface{loopIndex,net.FlagLoopback|net.FlagUp},nil}
func aliasInterfaces()([]aliasInterface,error){seen:=map[int]bool{loopIndex:true};for _,v:=range inventory{seen[v.index]=true};for index:=range extraAddresses{seen[index]=true};var out []aliasInterface;for n:=range seen{out=append(out,aliasInterface{n,net.FlagUp})};return out,nil}
func(i aliasInterface)Addrs()([]net.Addr,error){out:=append([]net.Addr(nil),extraAddresses[i.Index]...);for a,s:=range inventory{if s.index==i.Index{p:=netip.PrefixFrom(a,s.bits);out=append(out,aliasAddress(p.String()))}};return out,nil}
type aliasAddress string
func(a aliasAddress)Network()string{return "ip"}
func(a aliasAddress)String()string{return string(a)}
type aliasCommand struct{ctx context.Context;args []string}
func aliasCommandContext(ctx context.Context,name string,args ...string)*aliasCommand{return &aliasCommand{ctx,append([]string{name},args...)}}
func(c *aliasCommand)Run()error{
 if err:=c.ctx.Err();err!=nil{return err};a:=c.args
 if len(a)<5||a[0]!="/sbin/ifconfig"||a[1]!="lo0"||a[2]!="inet"{return errors.New("wrong original command")}
 address,err:=netip.ParseAddr(a[3]);if err!=nil{return err}
 add:=len(a)==7&&a[4]=="netmask"&&a[5]=="255.255.255.255"&&a[6]=="alias"
 remove:=len(a)==5&&a[4]=="-alias"
 if !add&&!remove{return errors.New("wrong exact alias command")}
 commands=append(commands,append([]string(nil),a...));apply,failure:=true,error(nil);if commandFault!=nil{apply,failure=commandFault(a)}
 if apply{if add{inventory[address]=macOSImportedExecutionAliasState{loopIndex,32}}else{delete(inventory,address)}}
 return failure
}
func resetAlias(){extraAddresses=map[int][]net.Addr{};inventory=map[netip.Addr]macOSImportedExecutionAliasState{};loopIndex=9;commands=nil;commandFault=nil;macOSImportedExecutionAliasGate=sync.Mutex{}}
func goodJoin(context.Context)error{return nil}
func ownAlias(t *testing.T)*macOSImportedExecutionAliasOwner{t.Helper();o,e:=macOSImportedExecutionOwnAliases(context.Background());if e!=nil||o==nil{t.Fatal("original alias creation failed",e)};return o}
func forceRelease(o *macOSImportedExecutionAliasOwner){if o!=nil{o.release()}}
func TestActualAliasOwner(t *testing.T){
 t.Run("owned-close-idempotent",func(t *testing.T){resetAlias();o:=ownAlias(t);defer forceRelease(o);if len(commands)!=2||len(inventory)!=2||o.index!=9{t.Fatal("both original aliases were not captured")};joined:=0
  if e:=o.Close(context.Background(),func(context.Context)error{joined++;if len(inventory)!=2{t.Fatal("aliases disappeared before original join")};return nil});e!=nil{t.Fatal(e)}
  if joined!=1||len(inventory)!=0||len(commands)!=4||!o.closed||o.unlock{t.Fatal("original alias close did not join and retire")}
  if e:=o.Close(context.Background(),func(context.Context)error{t.Fatal("closed owner rejoined replacement");return nil});e!=nil||len(commands)!=4{t.Fatal("closed owner repeated mutation")}
 })
 t.Run("unrelated-duplicate-ipv6",func(t *testing.T){resetAlias();extraAddresses[7]=[]net.Addr{aliasAddress("fe80::1/64")};extraAddresses[8]=[]net.Addr{aliasAddress("fe80::1/64")};o:=ownAlias(t);defer forceRelease(o);if e:=o.Close(context.Background(),goodJoin);e!=nil||len(extraAddresses)!=2{t.Fatal("unrelated duplicate IPv6 affected owned aliases")}})
 t.Run("collision-before-any-mutation",func(t *testing.T){resetAlias();inventory[macOSImportedExecutionAliases[1]]=macOSImportedExecutionAliasState{9,32};o,e:=macOSImportedExecutionOwnAliases(context.Background());defer forceRelease(o);if e==nil||o!=nil||len(commands)!=0||len(inventory)!=1{t.Fatal("alias collision allowed an earlier mutation")}})
 t.Run("partial-add-error-retains-intent",func(t *testing.T){resetAlias();commandFault=func(a []string)(bool,error){return true,errors.New("command failed after mutation")};o,e:=macOSImportedExecutionOwnAliases(context.Background());defer forceRelease(o);if e==nil||o==nil{t.Fatal("partial mutation lost original owner")};commandFault=nil
  if e=o.Close(context.Background(),goodJoin);e!=nil||len(inventory)!=0||len(commands)!=2{t.Fatal("attempted alias mutation escaped owned cleanup")}
 })
 t.Run("absent-attempted-mutation",func(t *testing.T){resetAlias();commandFault=func(a []string)(bool,error){return false,errors.New("no mutation")};o,e:=macOSImportedExecutionOwnAliases(context.Background());defer forceRelease(o);if e==nil||o==nil||len(o.added)!=1{t.Fatal("absent attempt lost original intent")};commandFault=nil;if e=o.Close(context.Background(),goodJoin);e!=nil||!o.closed||len(commands)!=1{t.Fatal("absent attempted alias was mutated during cleanup")}})
 for _,fault:=range []string{"mask","address-index","loopback-index"}{t.Run(fault,func(t *testing.T){resetAlias();o:=ownAlias(t);defer forceRelease(o);original:=inventory[macOSImportedExecutionAliases[1]]
  if fault=="mask"{inventory[macOSImportedExecutionAliases[1]]=macOSImportedExecutionAliasState{9,24}};if fault=="address-index"{inventory[macOSImportedExecutionAliases[1]]=macOSImportedExecutionAliasState{10,32}};if fault=="loopback-index"{loopIndex=10}
  if e:=o.Close(context.Background(),goodJoin);e==nil||len(commands)!=2||!o.unlock||o.closed{t.Fatal("foreign alias mask or index acquired deletion authority")}
  loopIndex=9;inventory[macOSImportedExecutionAliases[1]]=original;if e:=o.Close(context.Background(),goodJoin);e!=nil{t.Fatal(e)}
 })}
 t.Run("failed-join-retains-original-owner",func(t *testing.T){resetAlias();o:=ownAlias(t);defer forceRelease(o);failure:=errors.New("original worker not joined")
  if e:=o.Close(context.Background(),func(context.Context)error{return failure});!errors.Is(e,failure)||len(commands)!=2||len(inventory)!=2||!o.unlock||o.closed{t.Fatal("failed original join retired alias authority")};if e:=o.Close(context.Background(),goodJoin);e!=nil{t.Fatal(e)}
 })
 t.Run("partial-cleanup-retry",func(t *testing.T){resetAlias();o:=ownAlias(t);defer forceRelease(o);commandFault=func(a []string)(bool,error){if a[3]==macOSImportedExecutionAliases[0].String(){return false,errors.New("original removal failed")};return true,nil}
  if e:=o.Close(context.Background(),goodJoin);e==nil||len(o.added)!=1||len(inventory)!=1||!o.unlock||o.closed{t.Fatal("partial cleanup lost original retry authority")};commandFault=nil
  if e:=o.Close(context.Background(),goodJoin);e!=nil||len(inventory)!=0||!o.closed||len(commands)!=5{t.Fatal("partial cleanup retry replaced original inventory")}
 })
 t.Run("nil-join-refused",func(t *testing.T){resetAlias();o:=ownAlias(t);defer forceRelease(o);if o.Close(context.Background(),nil)==nil||len(commands)!=2{t.Fatal("missing original join acquired cleanup authority")};if e:=o.Close(context.Background(),goodJoin);e!=nil{t.Fatal(e)}})
 t.Run("cancelled-cleanup-retains-owner",func(t *testing.T){resetAlias();o:=ownAlias(t);defer forceRelease(o);ctx,cancel:=context.WithCancel(context.Background());cancel();if o.Close(ctx,goodJoin)==nil||len(commands)!=2||!o.unlock{t.Fatal("cancelled cleanup changed original alias owner")};if e:=o.Close(context.Background(),goodJoin);e!=nil{t.Fatal(e)}})
}
// The second Err observation occurs inside the real LockContext, after the
// public entry's first precheck. The original gate is held throughout.
type enteredContext struct{context.Context;mu sync.Mutex;n int;entered chan struct{}}
func(c *enteredContext)Err()error{c.mu.Lock();c.n++;if c.n==2{close(c.entered)};c.mu.Unlock();return c.Context.Err()}
func TestActualAliasCancelledWaiter(t *testing.T){resetAlias();macOSImportedExecutionAliasGate.Lock();locked:=true;defer func(){if locked{macOSImportedExecutionAliasGate.Unlock()}}();base,cancel:=context.WithCancel(context.Background());defer cancel();ctx:=&enteredContext{Context:base,entered:make(chan struct{})};done:=make(chan error,1)
 go func(){o,e:=macOSImportedExecutionOwnAliases(ctx);if o!=nil{o.release()};done<-e}()
 select{case <-ctx.entered:case <-time.After(time.Second):macOSImportedExecutionAliasGate.Unlock();locked=false;<-done;t.Fatal("cancelled alias waiter lost original context-aware admission")}
 cancel();select{case e:=<-done:if !errors.Is(e,context.Canceled)||len(commands)!=0{t.Fatal("cancelled alias waiter changed original inventory")}
 case <-time.After(time.Second):macOSImportedExecutionAliasGate.Unlock();locked=false;select{case <-done:case <-time.After(time.Second):t.Fatal("alias waiter did not join after release")};t.Fatal("cancelled alias waiter lost original context-aware admission")}
}
'''


def replace_once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('Actual alias source seam changed: ' + old)
    return source.replace(old, new, 1)


def extract(source):
    if not source.startswith('//go:build darwin && routervpn_controller_privileged\n\npackage main\n'):
        raise ValueError('Actual privileged Darwin alias source boundary changed')
    source = source.split('\n', 1)[1].lstrip('\n')
    source = replace_once(source, '\n\t"os/exec"', '')
    for old, new in [('net.InterfaceByName(', 'aliasInterfaceByName('), ('net.Interfaces()', 'aliasInterfaces()'), ('exec.CommandContext(', 'aliasCommandContext(')]:
        expected = 2 if old == 'exec.CommandContext(' else 1
        if source.count(old) != expected:
            raise ValueError('Actual OS adapter inventory changed: ' + old)
        source = source.replace(old, new)
    return source


def mutations(source):
    return {
        'cancelled-waiter': (replace_once(source, 'if err := desktopnetwork.LockContext(ctx, &macOSImportedExecutionAliasGate); err != nil {', '_ = desktopnetwork.LockContext\n\tmacOSImportedExecutionAliasGate.Lock()\n\tif err := ctx.Err(); err != nil {\n\t\tmacOSImportedExecutionAliasGate.Unlock()'), 'TestActualAliasCancelledWaiter', 'cancelled alias waiter lost original context-aware admission'),
        'attempted-intent': (replace_once(source, '\t\towner.added = append(owner.added, address)\n', '') .replace('\t\tactual, current, err := macOSImportedExecutionAliasInventory()', '\t\towner.added = append(owner.added, address)\n\t\tactual, current, err := macOSImportedExecutionAliasInventory()', 1), 'TestActualAliasOwner/partial-add-error-retains-intent', 'attempted alias mutation escaped owned cleanup'),
        'mask': (replace_once(source, 'if state != (macOSImportedExecutionAliasState{owner.index, 32}) {', 'if state.index != owner.index {'), 'TestActualAliasOwner/mask', 'foreign alias mask or index acquired deletion authority'),
        'address-index': (replace_once(source, 'if state != (macOSImportedExecutionAliasState{owner.index, 32}) {', 'if state.bits != 32 {'), 'TestActualAliasOwner/address-index', 'foreign alias mask or index acquired deletion authority'),
        'join': (replace_once(source, '\tif err := join(ctx); err != nil {\n\t\treturn err\n\t}', '\t_ = join(ctx)'), 'TestActualAliasOwner/failed-join-retains-original-owner', 'failed original join retired alias authority'),
    }


def validate_result(result, *, witness=None, selection=None):
    text = result.stdout + result.stderr
    if re.search(r'DATA RACE|panic:|fatal error:|build failed|\[build failed\]', text, re.I):
        raise RuntimeError('Unrelated compiler/runtime failure:\n' + text)
    if witness is None:
        passed = re.findall(r'^\s*--- PASS: (\S+) \(', text, re.M)
        started = re.findall(r'^=== RUN   (\S+)$', text, re.M)
        if (result.returncode != 0 or not re.search(r'^ok\s+router-vpn/probe\s', text, re.M)
                or sorted(passed) != sorted(VERDICTS) or sorted(started) != sorted(VERDICTS)
                or re.search(r'--- (?:FAIL|SKIP):|no tests to run', text)):
            raise RuntimeError('Actual alias positive did not pass:\n' + text)
    else:
        if not selection or not re.fullmatch(r'Test[A-Za-z0-9_]+(?:/[a-z0-9-]+)?', selection):
            raise RuntimeError('Causal alias verdict has no exact original test identity')
        expected = [selection.split('/')[0], selection] if '/' in selection else [selection]
        started = re.findall(r'^=== RUN   (\S+)$', text, re.M)
        failed = re.findall(r'^\s*--- FAIL: (\S+) \(', text, re.M)
        if sorted(started) != sorted(expected) or sorted(failed) != sorted(expected) or re.search(r'--- (?:PASS|SKIP):', text):
            raise RuntimeError('Causal alias verdict changed original run/fail inventory:\n' + text)
        lines = [line.strip() for line in text.splitlines() if re.match(r'\s*alias_test\.go:\d+: ', line)]
        if result.returncode != 1 or len(lines) != 1 or not re.fullmatch(r'alias_test\.go:\d+: ' + re.escape(witness), lines[0]) or 'FAIL\trouter-vpn/probe' not in text:
            raise RuntimeError('Alias causal control lacked its sole exact witness:\n' + text)
    return text


def execute(root=ROOT, go=None):
    root = Path(root); go = go or shutil.which('go')
    if not go:
        raise RuntimeError('Go compiler is required')
    script = Path(__file__).read_bytes()
    inputs = {p: (root / p).read_bytes() for p in (HELPER, LOCK)}
    source = extract(inputs[HELPER].decode())
    variants = {'shipping': (source, 'TestActualAlias(Owner|CancelledWaiter)', None), **mutations(source)}
    with tempfile.TemporaryDirectory(prefix='routervpn-alias-') as temporary:
        directory = Path(temporary); (directory/'probe').mkdir(); (directory/'internal/desktopnetwork').mkdir(parents=True)
        (directory/'go.mod').write_text('module router-vpn\n\ngo 1.24.0\n')
        (directory/'internal/desktopnetwork/desktop_network_lock.go').write_bytes(inputs[LOCK])
        (directory/'probe/alias_test.go').write_text(ADAPTER)
        env = dict(os.environ)
        # This stand-alone module uses only the selected standard library and
        # the original in-tree lock. Inherited target flags cannot select a
        # cross-compiled binary for this portable executable gate.
        for key in ('GOOS','GOARCH','GOARM','GOAMD64','GOTOOLDIR','GOROOT'):
            env.pop(key, None)
        for name, (body, selection, witness) in variants.items():
            (directory/'probe/alias.go').write_text(body)
            result = subprocess.run([go,'test','-v','-count=1','-timeout=15s','-run','^'+selection+'$','./probe'],cwd=directory,env=env,text=True,capture_output=True,timeout=45)
            validate_result(result,witness=witness,selection=selection)
            print('PASS actual alias '+name,flush=True)
    if Path(__file__).read_bytes() != script:
        raise RuntimeError("Alias extraction gate changed during execution")
    if any((root/p).read_bytes()!=content for p,content in inputs.items()):
        raise RuntimeError('Original alias/lock source changed during execution')
    receipt={'kind':'portable-darwin-imported-alias-owner','schema':1,'positive_roots':2,'positive_leaves':13,'positive_verdicts':list(VERDICTS),'gate_sha256':hashlib.sha256(script).hexdigest(),'causal_controls':len(variants)-1,'source_sha256':{p:hashlib.sha256(v).hexdigest() for p,v in inputs.items()},'native_alias_acceptance':False}
    print(json.dumps(receipt,sort_keys=True),flush=True)
    return receipt

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--root',type=Path,default=ROOT);parser.add_argument('--go');args=parser.parse_args();execute(args.root,args.go)
