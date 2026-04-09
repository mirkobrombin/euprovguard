package signature

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"time"
)

// VerificationResult holds the outcome of SBOM signature verification.
type VerificationResult struct {
	// Valid indicates whether the signature is cryptographically valid.
	Valid bool
	// SignedAt is the claimed signing time from the envelope.
	SignedAt string
	// Algorithm is the signature algorithm used.
	Algorithm string
	// TSAValid indicates whether a TSA token was present and accepted.
	TSAValid bool
	// TSAAt is the qualified timestamp time, if present.
	TSAAt string
	// EIDASStandard is the eIDAS standard reference in the envelope.
	EIDASStandard string
	// Errors contains any non-fatal verification warnings.
	Errors []string
}

// VerifySBOM loads a signed SBOM document from path and verifies its RSA signature
// using the provided public key. It returns a VerificationResult with validity flag and metadata.
func VerifySBOM(path string, pubKey *rsa.PublicKey) (VerificationResult, error) {
	result := VerificationResult{}

	doc, err := ReadSignedDocument(path)
	if err != nil {
		return result, fmt.Errorf("signature.VerifySBOM load %w", err)
	}

	result.SignedAt = doc.SignedAt
	result.Algorithm = doc.Algorithm
	result.EIDASStandard = doc.EIDASStandard

	// Verify signature
	if err := VerifyDocument(doc, pubKey); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("signature invalid: %v", err))
		log.Printf("[WARN] Signature verification FAILED: %v", err)
		return result, nil
	}
	result.Valid = true
	log.Printf("[INFO] Signature verification OK")

	// Check TSA token presence
	if doc.TSAToken != "" {
		result.TSAAt = doc.TSAAt
		result.TSAValid = true
		log.Printf("[INFO] TSA token present: %s", doc.TSAAt)
	} else {
		result.Errors = append(result.Errors,
			"no TSA timestamp present - eIDAS Article 26 qualified timestamp recommended")
		log.Printf("[WARN] No TSA timestamp in document")
	}

	return result, nil
}

// VerifySignatureBytes verifies a raw base64-encoded signature over data using the given public key.
// Returns nil if valid, or a wrapped error if verification fails.
func VerifySignatureBytes(pubKey *rsa.PublicKey, data []byte, sigBase64 string) error {
	sig, err := base64.StdEncoding.DecodeString(sigBase64)
	if err != nil {
		return fmt.Errorf("signature.VerifySignatureBytes decode %w", err)
	}
	return Verify(pubKey, data, sig)
}

// ParseSignedAt parses the SignedAt timestamp string ([RFC 3339]) into time.Time.
// Returns an error if the timestamp is unparseable.
func ParseSignedAt(signedAt string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, signedAt)
	if err != nil {
		return time.Time{}, fmt.Errorf("signature.ParseSignedAt %w", err)
	}
	return t, nil
}

// FormatResult returns a human-readable summary of a VerificationResult suitable for CLI output.
func FormatResult(result VerificationResult) string {
	status := "INVALID"
	if result.Valid {
		status = "VALID"
	}
	out := fmt.Sprintf(
		"Signature:     %s\n"+
			"Algorithm:     %s\n"+
			"Signed at:     %s\n"+
			"eIDAS std:     %s\n",
		status, result.Algorithm, result.SignedAt, result.EIDASStandard,
	)
	if result.TSAValid {
		out += fmt.Sprintf("TSA timestamp: PRESENT (%s)\n", result.TSAAt)
	} else {
		out += "TSA timestamp: NOT PRESENT\n"
	}
	for _, e := range result.Errors {
		out += fmt.Sprintf("WARNING: %s\n", e)
	}
	return out
}
