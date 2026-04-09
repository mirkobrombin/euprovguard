package signature

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"
)

// QES_STANDARD_VERSION identifies the eIDAS regulation version implemented.
const QES_STANDARD_VERSION = "eIDAS (EU) 2024/1183"

// QES_SIGNATURE_ALGORITHM is the algorithm identifier per ETSI TS 119 312.
const QES_SIGNATURE_ALGORITHM = "RSASSA-PKCS1-v1_5 with SHA-512"

// QESSignedDocument represents a signed SBOM document with QES metadata.
// This envelope format embeds the original document, its base64-encoded signature,
// and a metadata block asserting [eIDAS] compliance context.
type QESSignedDocument struct {
	// Version is the envelope schema version.
	Version string `json:"version"`
	// EIDASStandard references the regulation.
	EIDASStandard string `json:"eidas_standard"`
	// Algorithm is the signature algorithm identifier.
	Algorithm string `json:"algorithm"`
	// SignedAt is the ISO 8601 UTC time of signing.
	SignedAt string `json:"signed_at"`
	// Payload is the original document bytes (JSON SBOM).
	Payload json.RawMessage `json:"payload"`
	// Signature is the base64-encoded RSA signature over Payload.
	Signature string `json:"signature"`
	// TSAToken is the base64-encoded RFC 3161 timestamp token, if obtained.
	TSAToken string `json:"tsa_token,omitempty"`
	// TSAAt is the timestamp from the TSA response, if obtained.
	TSAAt string `json:"tsa_at,omitempty"`
	// CertificateHint is the optional certificate subject (non-binding).
	CertificateHint string `json:"certificate_hint,omitempty"`
}

// QESSignOptions configures QES signing behaviour.
type QESSignOptions struct {
	// PrivateKey is the RSA private key for signing.
	PrivateKey *rsa.PrivateKey
	// TSAURL is the RFC 3161 TSA endpoint (optional).
	TSAURL string
	// CertificateHint is a human-readable cert subject hint.
	CertificateHint string
}

// SignDocument creates a QESSignedDocument from raw payload bytes.
// It compacts the payload JSON for deterministic serialisation, signs with RSA-4096 SHA-512,
// and optionally obtains a TSA timestamp. It returns an envelope with the signature, payload,
// and metadata for eIDAS compliance.
func SignDocument(payload []byte, opts QESSignOptions) (*QESSignedDocument, error) {
	if opts.PrivateKey == nil {
		return nil, fmt.Errorf("qes.SignDocument: private key is required")
	}

	// Compact the JSON payload to ensure deterministic byte representation
	// across serialisation/deserialisation round-trips (MarshalIndent reformats
	// json.RawMessage, so we always sign the compact canonical form).
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, payload); err != nil {
		return nil, fmt.Errorf("qes.SignDocument: compact payload %w", err)
	}
	canonical := compacted.Bytes()

	sig, err := Sign(opts.PrivateKey, canonical)
	if err != nil {
		return nil, fmt.Errorf("qes.SignDocument %w", err)
	}

	doc := &QESSignedDocument{
		Version:         "1.0",
		EIDASStandard:   QES_STANDARD_VERSION,
		Algorithm:       QES_SIGNATURE_ALGORITHM,
		SignedAt:        time.Now().UTC().Format(time.RFC3339),
		Payload:         json.RawMessage(canonical),
		Signature:       base64.StdEncoding.EncodeToString(sig),
		CertificateHint: opts.CertificateHint,
	}

	// Obtain RFC 3161 qualified timestamp if TSA URL is configured.
	if opts.TSAURL != "" {
		tsaToken, tsaTime, err := RequestTimestamp(canonical, opts.TSAURL)
		if err != nil {
			// Non-fatal: log warning but continue without timestamp
			log.Printf("[WARN] TSA timestamp failed (%s): %v", opts.TSAURL, err)
		} else {
			doc.TSAToken = base64.StdEncoding.EncodeToString(tsaToken)
			doc.TSAAt = tsaTime.UTC().Format(time.RFC3339)
			log.Printf("[INFO] TSA timestamp obtained: %s", doc.TSAAt)
		}
	}

	return doc, nil
}

// VerifyDocument verifies the signature in a QESSignedDocument.
// The payload is compacted before verification to ensure byte-consistency with the canonical
// form that was signed. Returns nil if the signature is valid, or an error otherwise.
func VerifyDocument(doc *QESSignedDocument, pubKey *rsa.PublicKey) error {
	sigBytes, err := base64.StdEncoding.DecodeString(doc.Signature)
	if err != nil {
		return fmt.Errorf("qes.VerifyDocument decode signature %w", err)
	}

	// Compact the stored payload to reproduce the canonical bytes that were signed.
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, doc.Payload); err != nil {
		return fmt.Errorf("qes.VerifyDocument compact payload %w", err)
	}

	if err := Verify(pubKey, compacted.Bytes(), sigBytes); err != nil {
		return fmt.Errorf("qes.VerifyDocument %w", err)
	}
	log.Printf("[INFO] QES document verified: signedAt=%s algorithm=%s",
		doc.SignedAt, doc.Algorithm)
	return nil
}

// WriteSignedDocument serialises a QESSignedDocument to a JSON file.
// Returns an error if serialisation or write fails.
func WriteSignedDocument(doc *QESSignedDocument, path string) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("qes.WriteSignedDocument marshal %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("qes.WriteSignedDocument write %w: %s", err, path)
	}
	log.Printf("[INFO] Signed document written: %s (%d bytes)", path, len(data))
	return nil
}

// ReadSignedDocument deserialises a QESSignedDocument from a JSON file.
// Returns the document or an error if reading or parsing fails.
func ReadSignedDocument(path string) (*QESSignedDocument, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("qes.ReadSignedDocument read %w: %s", err, path)
	}
	var doc QESSignedDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("qes.ReadSignedDocument parse %w", err)
	}
	return &doc, nil
}
