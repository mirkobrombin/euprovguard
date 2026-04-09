package signature

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

// RSA_KEY_BITS is the mandated key size for [QES]-grade signatures per [ETSI TS 119 312].
const RSA_KEY_BITS = 4096

// RSA_HASH is the hash algorithm used for signing.
const RSA_HASH = crypto.SHA512

// LoadPrivateKey reads and decodes a [PEM]-encoded RSA private key from disk.
// It supports both PKCS#1 (RSA PRIVATE KEY) and PKCS#8 (PRIVATE KEY) formats.
// Returns an error if the file is unreadable, not [PEM]-formatted, or not an RSA key.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signature.LoadPrivateKey read %w: %s", err, path)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signature.LoadPrivateKey: no PEM block found in %s", path)
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signature.LoadPrivateKey PKCS1 %w", err)
		}
		log.Printf("[INFO] Loaded RSA-%d private key (PKCS#1) from %s", key.N.BitLen(), path)
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("signature.LoadPrivateKey PKCS8 %w", err)
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("signature.LoadPrivateKey: PKCS8 key is not RSA")
		}
		log.Printf("[INFO] Loaded RSA-%d private key (PKCS#8) from %s", key.N.BitLen(), path)
		return key, nil
	default:
		return nil, fmt.Errorf("signature.LoadPrivateKey: unsupported PEM type %q", block.Type)
	}
}

// LoadPublicKey reads and decodes a [PEM]-encoded RSA public key from disk.
// Returns an error if the file is unreadable, not [PEM]-formatted, or not an RSA key.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("signature.LoadPublicKey read %w: %s", err, path)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("signature.LoadPublicKey: no PEM block found in %s", path)
	}

	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signature.LoadPublicKey parse %w", err)
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("signature.LoadPublicKey: key is not RSA")
	}
	log.Printf("[INFO] Loaded RSA-%d public key from %s", key.N.BitLen(), path)
	return key, nil
}

// Sign produces a PKCS#1 v1.5 RSA-SHA512 signature over the provided data.
// Returns the signature bytes or an error if signing fails.
func Sign(key *rsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha512.New()
	h.Write(data)
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, RSA_HASH, digest)
	if err != nil {
		return nil, fmt.Errorf("signature.Sign %w", err)
	}
	log.Printf("[INFO] Signed %d bytes → %d byte signature (RSA-%d SHA-512)",
		len(data), len(sig), key.N.BitLen())
	return sig, nil
}

// Verify checks a PKCS#1 v1.5 RSA-SHA512 signature against data.
// Returns nil if the signature is valid, or an error if verification fails.
func Verify(key *rsa.PublicKey, data, sig []byte) error {
	h := sha512.New()
	h.Write(data)
	digest := h.Sum(nil)
	if err := rsa.VerifyPKCS1v15(key, RSA_HASH, digest, sig); err != nil {
		return fmt.Errorf("signature.Verify %w", err)
	}
	log.Printf("[INFO] Signature verified OK (RSA-%d SHA-512)", key.N.BitLen())
	return nil
}

// GenerateKeyPair generates a new RSA-4096 key pair and writes the private and public keys
// as [PEM] files. The private key is written in PKCS#8 format and the public key in PKIX format.
// Returns an error if generation or file write fails. Intended for development/testing only;
// production use requires a QTSP certificate.
func GenerateKeyPair(privPath, pubPath string) error {
	key, err := rsa.GenerateKey(rand.Reader, RSA_KEY_BITS)
	if err != nil {
		return fmt.Errorf("signature.GenerateKeyPair generate %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("signature.GenerateKeyPair marshal private %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("signature.GenerateKeyPair write private %w: %s", err, privPath)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return fmt.Errorf("signature.GenerateKeyPair marshal public %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil {
		return fmt.Errorf("signature.GenerateKeyPair write public %w: %s", err, pubPath)
	}

	log.Printf("[INFO] Generated RSA-%d key pair: %s / %s", RSA_KEY_BITS, privPath, pubPath)
	return nil
}
