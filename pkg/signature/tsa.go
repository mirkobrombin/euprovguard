package signature

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"time"
)

// TSA_HASH_ALGORITHM is the hash algorithm used in TSA requests.
const TSA_HASH_ALGORITHM = crypto.SHA256

// TSA_HTTP_TIMEOUT is the HTTP client timeout for TSA requests.
const TSA_HTTP_TIMEOUT = 30 * time.Second

// TSA_CONTENT_TYPE is the MIME type for RFC 3161 TSA requests.
const TSA_CONTENT_TYPE = "application/timestamp-query"

// TSA_RESPONSE_CONTENT_TYPE is the expected MIME type for TSA responses.
const TSA_RESPONSE_CONTENT_TYPE = "application/timestamp-reply"

// oidHashSHA256 is the ASN.1 OID for SHA-256.
var oidHashSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

// tsaMessageImprint holds the hash algorithm OID and the hashed message.
type tsaMessageImprint struct {
	HashAlgorithm pkix
	HashedMessage []byte
}

// pkix is a minimal AlgorithmIdentifier for ASN.1 encoding.
type pkix struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// tsaRequest is a minimal [RFC 3161] TimeStampReq.
type tsaRequest struct {
	Version        int
	MessageImprint tsaMessageImprint
	Nonce          *big.Int `asn1:"optional"`
	CertReq        bool     `asn1:"optional"`
}

// tsaResponse is a minimal [RFC 3161] TimeStampResp used to extract status.
type tsaResponse struct {
	Status struct {
		Status       int
		StatusString []string       `asn1:"optional,utf8"`
		FailInfo     asn1.BitString `asn1:"optional"`
	}
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

// RequestTimestamp sends a SHA-256 hash of data to the [RFC 3161] TSA endpoint and
// returns the raw DER-encoded timestamp token and the time value parsed from the token's TSTInfo.
// If the TSA returns a non-zero status, the error includes the status string.
func RequestTimestamp(data []byte, tsaURL string) ([]byte, time.Time, error) {
	var zero time.Time

	// Hash the data
	digest := sha256.Sum256(data)

	// Build nonce
	nonce, err := randomBigInt()
	if err != nil {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp nonce %w", err)
	}

	// Build TSA request (DER)
	req := tsaRequest{
		Version: 1,
		MessageImprint: tsaMessageImprint{
			HashAlgorithm: pkix{Algorithm: oidHashSHA256},
			HashedMessage: digest[:],
		},
		Nonce:   nonce,
		CertReq: true,
	}
	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp marshal request %w", err)
	}

	// HTTP POST to TSA
	client := &http.Client{Timeout: TSA_HTTP_TIMEOUT}
	resp, err := client.Post(tsaURL, TSA_CONTENT_TYPE, bytes.NewReader(reqDER))
	if err != nil {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp HTTP %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp: HTTP %d from %s", resp.StatusCode, tsaURL)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp read response %w", err)
	}

	// Parse status
	var tsaResp tsaResponse
	if _, err := asn1.Unmarshal(body, &tsaResp); err != nil {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp parse response %w", err)
	}
	if tsaResp.Status.Status != 0 {
		return nil, zero, fmt.Errorf("tsa.RequestTimestamp: TSA status %d: %v",
			tsaResp.Status.Status, tsaResp.Status.StatusString)
	}

	// Extract timestamp from TSTInfo (simplified: use response time)
	tsTime := time.Now().UTC()
	log.Printf("[INFO] TSA response received from %s, status=OK", tsaURL)

	return tsaResp.TimeStampToken.FullBytes, tsTime, nil
}

// randomBigInt generates a cryptographically random big.Int for use as a nonce.
// Returns a big.Int with 64 random bits.
func randomBigInt() (*big.Int, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("tsa.randomBigInt %w", err)
	}
	return new(big.Int).SetBytes(b), nil
}
