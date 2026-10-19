package snowflake_client

import "context"

// Tongue catches one peer using the collector's captured session context.
type Tongue interface {
	Catch(context.Context) (*WebRTCPeer, error)
}
