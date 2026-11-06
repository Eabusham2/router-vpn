package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"router-vpn/internal/hopmeasure"
	"time"
)

type importedDNSEngine interface{ DNSProof(context.Context) error }

func (c *Controller) verifyImportedEntry(ctx context.Context) error {
	if c.imported == nil {
		return errors.New("imported entry lost its captured native owner")
	}
	if err := c.requireValidContext(ctx); err != nil {
		return err
	}
	if err := proveExternalPublicIP(ctx, c.engine.Dial, c.meta.EntryTag, c.imported.publicIP, c.externalResponseTLS); err != nil {
		return err
	}
	dns, ok := c.engine.(importedDNSEngine)
	if !ok {
		return errors.New("imported path has no captured native DNS proof")
	}
	if err := dns.DNSProof(ctx); err != nil {
		return err
	}
	return c.requireValidContext(ctx)
}

// NewImportedHopMeasurement binds both hop kinds to the successful retained
// owner, rather than interpreting public metadata as paired-entry authority.
func (c *Controller) NewImportedHopMeasurement(engine hopmeasure.Engine) (*hopmeasure.Service, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if c == nil || c.imported == nil || engine == nil || c.HealthyContext(ctx) != nil {
		return nil, errors.New("imported hop measurement requires its successful original path")
	}
	identity, err := externalObservedIdentity(ctx, engine)
	if err != nil {
		return nil, err
	}
	selected, err := externalObservedSelection(ctx, c.engine)
	if err != nil {
		return nil, err
	}
	e := &importedMeasurementEngine{owner: c, engine: engine, identity: identity}
	if identity != c.engineID+":"+selected {
		return nil, errors.New("imported measurement owner changed")
	}
	if _, err := e.IdentityContext(ctx); err != nil {
		return nil, err
	}
	return hopmeasure.New(e, []hopmeasure.Hop{{ID: c.meta.EntryID, Role: "entry", Tag: externalEntryTag, Kind: "public-path"}, {ID: c.meta.ExitID, Role: "exit", Tag: "proxy", Kind: "private-node", API: c.meta.ExitAPI, Token: c.meta.ExitToken, Proof: c.meta.ExitNodeID}})
}

type importedMeasurementEngine struct {
	owner    *Controller
	engine   hopmeasure.Engine
	identity string
}

func (e *importedMeasurementEngine) Identity() string {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	identity, _ := e.IdentityContext(ctx)
	return identity
}
func (e *importedMeasurementEngine) IdentityContext(ctx context.Context) (string, error) {
	if err := e.owner.HealthyContext(ctx); err != nil {
		return "", err
	}
	identity, err := externalObservedIdentity(ctx, e.engine)
	if err != nil {
		return "", err
	}
	if e.identity == "" || identity != e.identity {
		return "", errors.New("imported measurement owner changed")
	}
	return e.identity + ":" + e.owner.SourceSHA256(), nil
}
func (e *importedMeasurementEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if _, err := e.IdentityContext(ctx); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch tag {
	case externalEntryTag:
		tag = e.owner.meta.EntryTag
	case "proxy":
	default:
		return nil, errors.New("unowned imported measurement route")
	}
	connection, err := e.engine.Dial(ctx, tag, address)
	_, observeErr := e.IdentityContext(ctx)
	if err != nil || ctx.Err() != nil || observeErr != nil {
		if connection != nil {
			err = errors.Join(err, connection.Close())
		}
		return nil, errors.Join(err, observeErr, ctx.Err(), errors.New("imported measurement changed during dial"))
	}
	return connection, nil
}
func (e *importedMeasurementEngine) VerifyMeasurement(ctx context.Context) error {
	if _, err := e.IdentityContext(ctx); err != nil {
		return err
	}
	proof := &trial{owner: e.owner, tag: LocalTag}
	if e.owner.hasImportedOpenVPN() {
		active := e.owner.openvpnActive.Load()
		if active == nil || active.tag != LocalTag {
			return errors.New("imported measurement lost its original OpenVPN proof")
		}
		proof.openvpnRemote, proof.openvpnEntryMTU = &active.receipt, active.entryMTU
	}
	return proof.Verify(ctx)
}

func (c *Controller) MatchesEngine(engine Engine) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if c == nil || engine == nil || c.HealthyContext(ctx) != nil {
		return false
	}
	identity, err := externalObservedIdentity(ctx, engine)
	return err == nil && identity == c.engineID
}
