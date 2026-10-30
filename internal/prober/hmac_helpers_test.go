package prober

// Test-side spellings of the reusable HMAC state. Production has only
// probeMACer; these helpers keep the tests concise without reintroducing a
// second verifier implementation that production might drift from.

// macerOrNil mirrors the server's "no rotation" spelling: an empty secret
// must never become a verifier, because a zero-length HMAC key is a valid
// key and would accept every frame tagged with HMAC-SHA256("").
func macerOrNil(secret string) *probeMACer {
	if secret == "" {
		return nil
	}
	return newProbeMACer(secret)
}

// headerTag builds the v0.7 header tag under secret.
func headerTag(secret string, seq, ts uint64) [8]byte {
	return newProbeMACer(secret).digestHeader(seq, ts)
}

// frameTag builds the full-frame tag under secret.
func frameTag(secret string, frame []byte) [8]byte {
	return newProbeMACer(secret).digestFrame(frame)
}
