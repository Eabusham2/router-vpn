package dnsmeasure

// ValidateUsableDNSResponse requires the exact fresh question and transaction,
// complete bounded framing, and a usable public A answer (possibly via CNAME).
// It does not establish transport ownership; the caller retains that authority.
func ValidateUsableDNSResponse(query, response []byte) error {
	return validateAnswer(query, response)
}
