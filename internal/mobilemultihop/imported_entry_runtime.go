package mobilemultihop

import (
	"context"
	"errors"
	"net"
	"router-vpn/internal/hopmeasure"
)

type importedDNSEngine interface{ DNSProof(context.Context) error }

func (c *Controller) verifyImportedEntry(ctx context.Context) error {
	if c.imported == nil || c.requireValid() != nil {
		return errors.New("imported entry lost its captured native owner")
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
	return c.requireValid()
}

// NewImportedHopMeasurement binds both hop kinds to the successful retained
// owner, rather than interpreting public metadata as paired-entry authority.
func (c *Controller) NewImportedHopMeasurement(engine hopmeasure.Engine) (*hopmeasure.Service, error) {
	if c == nil || c.imported == nil || !c.Healthy() || engine == nil {
		return nil, errors.New("imported hop measurement requires its successful original path")
	}
	e := &importedMeasurementEngine{owner: c, engine: engine, identity: engine.Identity()}
	if e.identity != c.engineID+":"+c.engine.Selected() || e.Identity() == "" {
		return nil, errors.New("imported measurement owner changed")
	}
	return hopmeasure.New(e, []hopmeasure.Hop{{ID: c.meta.EntryID, Role: "entry", Tag: externalEntryTag, Kind: "public-path"}, {ID: c.meta.ExitID, Role: "exit", Tag: "proxy", Kind: "private-node", API: c.meta.ExitAPI, Token: c.meta.ExitToken, Proof: c.meta.ExitNodeID}})
}

type importedMeasurementEngine struct {
	owner    *Controller
	engine   hopmeasure.Engine
	identity string
}

func (e *importedMeasurementEngine) Identity() string {
	if !e.owner.Healthy() || e.identity == "" || e.engine.Identity() != e.identity {
		return ""
	}
	return e.identity + ":" + e.owner.SourceSHA256()
}
func (e *importedMeasurementEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if e.Identity() == "" || ctx == nil {
		return nil, errors.New("imported measurement retired")
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
	if err != nil || ctx.Err() != nil || e.Identity() == "" {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, errors.Join(err, ctx.Err(), errors.New("imported measurement changed during dial"))
	}
	return connection, nil
}
func (e *importedMeasurementEngine) VerifyMeasurement(ctx context.Context) error {
	if e.Identity() == "" {
		return errors.New("imported measurement retired")
	}
	return (&trial{owner: e.owner, tag: LocalTag}).Verify(ctx)
}

func (c *Controller) MatchesEngine(engine Engine) bool {
	return c != nil && c.Healthy() && engine != nil && engine.Identity() == c.engineID
}
