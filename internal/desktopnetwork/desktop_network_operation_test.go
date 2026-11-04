package desktopnetwork

import (
	"context"
	"testing"
)

func TestNetworkRetainedLifetimeKeepsOriginalOperationBudget(t *testing.T) {
	owner, native := networkTestTracker(t, nil)
	first, finish := context.WithCancel(context.Background())
	if err := owner.CurrentContext(first); err != nil {
		t.Fatal(err)
	}
	finish()
	if err := owner.Current(); err != nil {
		t.Fatal("finished observation cancelled independently retained lifetime", err)
	}
	operation, cancel := context.WithCancel(context.Background())
	native.mu.Lock()
	native.barrier = cancel
	native.mu.Unlock()
	if err := owner.CurrentContext(operation); err == nil {
		t.Fatal("original request cancellation during native barrier became success")
	}
	if err := owner.Current(); err == nil {
		t.Fatal("later request cleared failed original observation")
	}
}

func TestNetworkInitializationCannotAdoptCancelledCaller(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	native := &networkFakeNative{snapshot: networkTestPhysical(), barrier: cancel}
	owner := &Tracker{ctx: context.Background(), native: native, initializing: true}
	if err := owner.initialize(ctx); err == nil || !owner.initializing {
		t.Fatal("retained lifetime borrowed cancelled startup acceptance", err)
	}
	if err := owner.Current(); err == nil {
		t.Fatal("failed initialization produced a current receipt")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNetworkStartupTransitionKeepsOriginalOperationBudget(t *testing.T) {
	for _,stage:=range []string{"begin","end"}{t.Run(stage,func(t *testing.T){
		owner,native:=networkTestTracker(t,nil)
		ctx,cancel:=context.WithCancel(context.Background())
		if stage=="end" {if err:=owner.Begin(ctx,nil);err!=nil{t.Fatal(err)}}
		native.mu.Lock();native.barrier=cancel;native.mu.Unlock()
		var err error
		if stage=="begin"{err=owner.Begin(ctx,nil)}else{err=owner.End(ctx,nil)}
		if err==nil{t.Fatal("native startup transition adopted a cancelled original caller")}
		if err:=owner.Current();err==nil{t.Fatal("cancelled startup transition recovered into a current epoch")}
	})}
}
