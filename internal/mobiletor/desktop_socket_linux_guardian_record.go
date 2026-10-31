package mobiletor

import (
	"errors"

	"router-vpn/internal/linuxprocess"
)

// DesktopLinuxGuardianRecord is comparison data observed through the actual
// engine and clone-created guardian witnesses. It cannot create either
// process or authorize adoption of a persisted journal's numeric PID.
type DesktopLinuxGuardianRecord struct {
	Engine   linuxprocess.Observation `json:"engine"`
	Guardian linuxprocess.Observation `json:"guardian"`
}

func (r DesktopLinuxGuardianRecord) Validate() error {
	e, g := r.Engine, r.Guardian
	if e.Validate() != nil || g.Validate() != nil || e.ProcessID == g.ProcessID || e.ProcProcessID == g.ProcProcessID ||
		g.ProcParentID != e.ProcProcessID || g.BootID != e.BootID || g.StartTicks < e.StartTicks || g.Image != e.Image ||
		g.NetworkNamespace != e.NetworkNamespace || g.PIDNamespace != e.PIDNamespace {
		return errors.New("Linux guardian record lost its original created engine relationship")
	}
	return nil
}
