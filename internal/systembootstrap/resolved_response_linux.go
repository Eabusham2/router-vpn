//go:build linux

package systembootstrap

// ResolvedResponseSuccess validates the complete original question and the
// same bounded address/CNAME semantics used when adopting a bootstrap answer.
// A valid NXDOMAIN is a negative result, never a winner over an independent
// equal-best scope which may still return a positive answer.
func ResolvedResponseSuccess(question, response []byte) (bool, error) {
	if _, err := addressesFor(question, response); err != nil {
		return false, err
	}
	return response[3]&15 == 0, nil
}
