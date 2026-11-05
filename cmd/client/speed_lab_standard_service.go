package main

import (
	"context"
	"net"
)

// A platform service retains the same connection/source authority while its
// public node identity differs from the private policy profile used to launch it.
type speedLabStandardServiceIdentity interface {
	current(context.Context, *app, speedLabPathIdentity) error
	restorePlan(context.Context, *app) (speedLabRestorePlan, error)
	verify(context.Context, *app, speedLabPathIdentity) error
	DialContext(context.Context, string, string) (net.Conn, error)
}
type speedLabStandardServiceRestore interface {
	restart(context.Context, *app) error
}
