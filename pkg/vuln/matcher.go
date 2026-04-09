package vuln

import (
	"fmt"
	"log"
	"strings"
)

// CVE_DATABASE_PATH is deprecated - no longer used since CVE matching is now live via OSV/EUVD.
const CVE_DATABASE_PATH = "cves.json" // Deprecated: kept for backward compatibility only

// Severity represents the CVSS severity level of a vulnerability.
type Severity string

const (
	SEVERITY_CRITICAL Severity = "CRITICAL"
	SEVERITY_HIGH     Severity = "HIGH"
	SEVERITY_MEDIUM   Severity = "MEDIUM"
	SEVERITY_LOW      Severity = "LOW"
	SEVERITY_NONE     Severity = "NONE"
)

// CVEEntry represents a single CVE record from the embedded database or [EUVD] API.
type CVEEntry struct {
	// ID is the CVE identifier, e.g. "CVE-2024-12345", or EUVD ID in live mode.
	ID string `json:"id"`
	// Package is the affected package name (lowercase).
	Package string `json:"package"`
	// Ecosystem is the package ecosystem: "go", "cargo", "npm", "pypi".
	Ecosystem string `json:"ecosystem"`
	// VersionsAffected lists affected version ranges as strings.
	VersionsAffected []string `json:"versions_affected"`
	// FixedVersion is the first version that includes a fix ("" = no fix).
	FixedVersion string `json:"fixed_version"`
	// Severity is the CVSS severity level.
	Severity Severity `json:"severity"`
	// CVSS is the CVSS base score (0.0 - 10.0).
	CVSS float64 `json:"cvss"`
	// Description is a brief human-readable description of the vulnerability.
	Description string `json:"description"`
	// CWE is the associated CWE identifier, e.g. "CWE-79".
	CWE string `json:"cwe"`
	// EuvdID is the ENISA EUVD identifier, e.g. "EUVD-2026-12345" (live mode only).
	EuvdID string `json:"euvd_id,omitempty"`
	// ScoreMethod is the CVSS scoring method: "CVSSv31" or "CVSSv40".
	// Defaults to "CVSSv31" for embedded DB entries.
	ScoreMethod string `json:"score_method,omitempty"`
	// Exploited indicates the vulnerability is being actively exploited (live mode).
	Exploited bool `json:"exploited,omitempty"`
	// Source is the data origin: "embedded" or "EUVD".
	Source string `json:"source,omitempty"`
}

// Finding represents a matched CVE for a specific dependency.
type Finding struct {
	// CVE is the matched CVE entry.
	CVE CVEEntry
	// Component is the package name that was matched.
	Component string
	// Version is the matched package version.
	Version string
}

// Matcher holds the loaded CVE database for pattern matching.
type Matcher struct {
	entries []CVEEntry
}

// Dependency is a minimal interface-compatible struct used for matching.
// It decouples the vuln package from the scanner package to avoid import cycles.
type Dependency struct {
	// Name is the package name.
	Name string
	// Version is the package version string.
	Version string
	// Ecosystem is one of "go", "cargo", "npm", "pypi".
	Ecosystem string
}

// NewMatcher is deprecated and no longer used.
// All vulnerability matching is now performed via live OSV.dev and EUVD queries.
// Deprecated: Use MatchLive instead.
func NewMatcher(ignored ...interface{}) (*Matcher, error) {
	return nil, fmt.Errorf("NewMatcher is deprecated; use MatchLive for live OSV+EUVD queries")
}

// Match checks a list of dependencies against the CVE database and returns all findings.
// Matching is case-insensitive on package name and ecosystem. Returns one entry per (dependency, CVE) match.
func (m *Matcher) Match(deps []Dependency) []Finding {
	var findings []Finding
	for _, dep := range deps {
		for _, entry := range m.entries {
			if strings.EqualFold(entry.Package, dep.Name) &&
				strings.EqualFold(entry.Ecosystem, dep.Ecosystem) {
				findings = append(findings, Finding{
					CVE:       entry,
					Component: dep.Name,
					Version:   dep.Version,
				})
				log.Printf("[WARN] %s matched %s (CVSS %.1f %s) in %s@%s",
					entry.ID, entry.CWE, entry.CVSS, entry.Severity,
					dep.Name, dep.Version)
			}
		}
	}
	return findings
}

// CountBySeverity returns a map of severity level to count of findings.
func CountBySeverity(findings []Finding) map[Severity]int {
	counts := map[Severity]int{
		SEVERITY_CRITICAL: 0,
		SEVERITY_HIGH:     0,
		SEVERITY_MEDIUM:   0,
		SEVERITY_LOW:      0,
		SEVERITY_NONE:     0,
	}
	for _, f := range findings {
		counts[f.CVE.Severity]++
	}
	return counts
}
