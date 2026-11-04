package mobiletor

// Only a native adapter that has not submitted a grant may return this result.
// The exact attempted request binds the evidence to one serialized broker
// operation. An unknown send/application outcome must retain its new sequence.
type desktopSocketGrantNotSubmitted struct {
	request DesktopSocketGrant
	cause   error
}

func (e *desktopSocketGrantNotSubmitted) Error() string { return e.cause.Error() }
func (e *desktopSocketGrantNotSubmitted) Unwrap() error { return e.cause }

func desktopSocketUnsubmittedGrant(request DesktopSocketGrant, cause error) error {
	return &desktopSocketGrantNotSubmitted{request: request, cause: cause}
}
