package vuln

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// OSV_API_URL is the OSV.dev batch query endpoint.
const OSV_API_URL = "https://api.osv.dev/v1/query"

// OSV_HTTP_TIMEOUT is the per-request HTTP timeout for OSV queries.
const OSV_HTTP_TIMEOUT = 10 * time.Second

// osvQueryRequest is the POST body sent to the OSV /v1/query endpoint.
type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	// Version is omitted for non-pinned ecosystems; OSV then returns all known vulns.
	Version string `json:"version,omitempty"`
}

// osvVuln is a single vulnerability record returned by OSV.
type osvVuln struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
	Details string   `json:"details"`
	// DatabaseSpecific contains GHSA-level severity labels (CRITICAL/HIGH/MODERATE/LOW).
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// osvQueryResponse is the top-level OSV /v1/query response envelope.
type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

// osvEcosystem maps internal ecosystem tags to OSV identifiers.
func osvEcosystem(dep Dependency) string {
	switch strings.ToLower(dep.Ecosystem) {
	case "go":
		return "Go"
	case "npm":
		return "npm"
	case "pypi":
		return "PyPI"
	case "cargo":
		return "crates.io"
	case "nuget":
		return "NuGet"
	case "vcpkg", "conan":
		// No OSV coverage for C/C++ package managers - include in SBOM but skip vuln scan
		return ""
	default:
		return ""
	}
}

// osvVersion normalizes a dependency version for the OSV query.
func osvVersion(dep Dependency) string {
	ver := dep.Version
	if strings.ToLower(dep.Ecosystem) == "go" {
		ver = strings.TrimPrefix(ver, "v")
		if idx := strings.Index(ver, "+"); idx != -1 {
			ver = ver[:idx]
		}
	}
	return ver
}

// QueryOSV fetches vulnerabilities from OSV.dev.
func QueryOSV(dep Dependency) ([]osvVuln, error) {
	eco := osvEcosystem(dep)
	if eco == "" {
		return nil, nil
	}

	var req osvQueryRequest
	req.Package.Name = dep.Name
	req.Package.Ecosystem = eco
	req.Version = osvVersion(dep)

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vuln.QueryOSV marshal: %w", err)
	}

	client := &http.Client{Timeout: OSV_HTTP_TIMEOUT}
	resp, err := client.Post(OSV_API_URL, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("vuln.QueryOSV request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln.QueryOSV HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vuln.QueryOSV read: %w", err)
	}

	var qr osvQueryResponse
	if err := json.Unmarshal(data, &qr); err != nil {
		return nil, fmt.Errorf("vuln.QueryOSV parse: %w", err)
	}

	var result []osvVuln
	for _, v := range qr.Vulns {
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				result = append(result, v)
				break
			}
		}
	}
	return result, nil
}

// ExtractCVEFromOSV returns the first CVE alias from an OSV record.
func ExtractCVEFromOSV(v osvVuln) string {
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return v.ID
}

// osvSeverityToFloat maps OSV severity labels to CVSS scores.
func osvSeverityToFloat(sev string) float64 {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.5
	case "MODERATE", "MEDIUM":
		return 5.5
	case "LOW":
		return 2.0
	default:
		return 5.0
	}
}
