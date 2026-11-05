package desktopnetwork

import (
	"bytes"
	"context"
	"errors"
	"net"
)

// InterfaceContext projects the same interface fields and address strings as
// net.InterfaceByIndex/Addrs, while retaining the original read operation.
// It supplies observation only; the caller still proves its captured network
// generation before and after using these values in a path identity.
func InterfaceContext(ctx context.Context, index int) (*net.Interface, []net.Addr, error) {
	if ctx == nil || index < 1 || uint64(index) > 0x7fffffff {
		return nil, nil, errors.New("interface observation requires its original caller and index")
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	current, addresses, err := interfaceContextNative(ctx, index)
	if err != nil || ctx.Err() != nil {
		return nil, nil, errors.Join(err, ctx.Err())
	}
	if current == nil || current.Index != index {
		return nil, nil, errors.New("interface observation changed its requested index")
	}
	return current, addresses, nil
}

func sameInterface(first, second *net.Interface) bool {
	return first != nil && second != nil && first.Index == second.Index && first.Name == second.Name &&
		first.MTU == second.MTU && first.Flags == second.Flags && bytes.Equal(first.HardwareAddr, second.HardwareAddr)
}

// InterfacesContext inventories indices and native metadata under one original
// observation. Callers must recheck each selected interface when reading addresses.
func InterfacesContext(ctx context.Context) ([]net.Interface, error) {
	if ctx == nil {
		return nil, errors.New("interface inventory requires its original caller")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result, err := interfacesContextNative(ctx)
	if err != nil || ctx.Err() != nil {
		return nil, errors.Join(err, ctx.Err())
	}
	return result, nil
}
