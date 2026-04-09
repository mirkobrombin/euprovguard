package vuln

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// EUVD_API_BASE is the ENISA EUVD REST API base URL.
const EUVD_API_BASE = "https://euvdservices.enisa.europa.eu/api"

// EUVD_SEARCH_SIZE is the default number of results per dependency query.
const EUVD_SEARCH_SIZE = 50

// EUVD_HTTP_TIMEOUT is the per-request HTTP timeout.
const EUVD_HTTP_TIMEOUT = 10 * time.Second

// euvdProductEntry is a product record within an EUVD vulnerability item.
type euvdProductEntry struct {
	Product struct {
		Name string `json:"name"`
	} `json:"product"`
	ProductVersion string `json:"product_version"`
}

// euvdItem is the raw JSON record returned by the EUVD API.
type euvdItem struct {
	ID               string             `json:"id"`
	Description      string             `json:"description"`
	DatePublished    string             `json:"datePublished"`
	BaseScore        float64            `json:"baseScore"`
	BaseScoreVersion string             `json:"baseScoreVersion"`
	Aliases          string             `json:"aliases"`
	ExploitedSince   string             `json:"exploitedSince"`
	Products         []euvdProductEntry `json:"enisaIdProduct"`
}

// euvdSearchResponse wraps the /search endpoint JSON envelope.
type euvdSearchResponse struct {
	Items []euvdItem `json:"items"`
	Total int        `json:"total"`
}

// EuvdSnapshot is the EUVD state metadata for reports.
// Auditors can independently verify the snapshot via the EUVD API.
type EuvdSnapshot struct {
	// ScanTimestamp is the RFC3339 UTC time the live scan was performed.
	ScanTimestamp string `json:"scanTimestamp"`
	// LastEuvdId is the most recent EUVD identifier at scan time.
	LastEuvdId string `json:"lastEuvdId"`
	// Source identifies the data origin.
	Source string `json:"source"`
}

// normalizeCVSS maps a CVSS base score to a Severity constant.
func normalizeCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SEVERITY_CRITICAL
	case score >= 7.0:
		return SEVERITY_HIGH
	case score >= 4.0:
		return SEVERITY_MEDIUM
	case score > 0.0:
		return SEVERITY_LOW
	default:
		return SEVERITY_NONE
	}
}

// extractCVEAlias returns the first "CVE-" prefixed alias from a newline-separated aliases string,
// or falls back to the EUVD ID when no CVE alias is present.
func extractCVEAlias(aliases, euvdId string) string {
	for _, a := range strings.Split(aliases, "\n") {
		a = strings.TrimSpace(a)
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return euvdId
}

// euvdItemToEntry converts an euvdItem to a CVEEntry.
// It applies a strict product name filter to avoid false positives.
func euvdItemToEntry(item euvdItem, depName string) (CVEEntry, bool) {
	matched := false
	for _, p := range item.Products {
		if strings.EqualFold(p.Product.Name, depName) {
			matched = true
			break
		}
	}
	if !matched {
		return CVEEntry{}, false
	}

	cveID := extractCVEAlias(item.Aliases, item.ID)

	method := "CVSSv31"
	if item.BaseScoreVersion == "4.0" {
		method = "CVSSv40"
	}

	return CVEEntry{
		ID:          cveID,
		EuvdID:      item.ID,
		Package:     strings.ToLower(depName),
		Severity:    normalizeCVSS(item.BaseScore),
		CVSS:        item.BaseScore,
		Description: item.Description,
		ScoreMethod: method,
		Exploited:   item.ExploitedSince != "",
		Source:      "EUVD",
	}, true
}

// QueryEUVD searches the [EUVD] API for vulnerabilities affecting the named dependency.
// Results are filtered by exact product name match to avoid false positives. Deduplication
// is applied by EUVD ID within the result set.
func QueryEUVD(dep string, size int) ([]CVEEntry, error) {
	if size <= 0 || size > 100 {
		size = EUVD_SEARCH_SIZE
	}

	client := &http.Client{Timeout: EUVD_HTTP_TIMEOUT}
	reqURL := fmt.Sprintf("%s/search?keywords=%s&size=%d",
		EUVD_API_BASE, url.QueryEscape(dep), size)

	resp, err := client.Get(reqURL)
	if err != nil {
		return nil, fmt.Errorf("vuln.QueryEUVD: HTTP GET %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, fmt.Errorf("vuln.QueryEUVD: EUVD rate limited (HTTP 429) - reduce concurrency or retry")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln.QueryEUVD: unexpected HTTP status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vuln.QueryEUVD: read body %w", err)
	}

	var search euvdSearchResponse
	if err := json.Unmarshal(body, &search); err != nil {
		return nil, fmt.Errorf("vuln.QueryEUVD: parse response %w", err)
	}

	seen := make(map[string]bool)
	var entries []CVEEntry
	for _, item := range search.Items {
		entry, ok := euvdItemToEntry(item, dep)
		if !ok {
			continue
		}
		if seen[entry.EuvdID] {
			continue
		}
		seen[entry.EuvdID] = true
		entries = append(entries, entry)
	}

	return entries, nil
}

// GetSnapshot fetches [EUVD] database state metadata by retrieving the most recent entry.
// The returned EuvdSnapshot can be embedded in compliance reports as an audit attestation.
func GetSnapshot() (EuvdSnapshot, error) {
	snap := EuvdSnapshot{
		ScanTimestamp: time.Now().UTC().Format(time.RFC3339),
		Source:        "OSV+EUVD (ENISA)",
	}

	client := &http.Client{Timeout: EUVD_HTTP_TIMEOUT}
	reqURL := fmt.Sprintf("%s/lastvulnerabilities?page=0&size=1", EUVD_API_BASE)

	resp, err := client.Get(reqURL)
	if err != nil {
		return snap, fmt.Errorf("vuln.GetSnapshot: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return snap, fmt.Errorf("vuln.GetSnapshot: read body %w", err)
	}

	var items []euvdItem
	if err := json.Unmarshal(body, &items); err != nil {
		return snap, fmt.Errorf("vuln.GetSnapshot: parse %w", err)
	}

	if len(items) > 0 {
		snap.LastEuvdId = items[0].ID
	}

	return snap, nil
}

// NormalizeCVSS is the exported alias for normalizeCVSS for use in tests.
func NormalizeCVSS(score float64) Severity {
	return normalizeCVSS(score)
}

// ExtractCVEAlias is the exported alias for extractCVEAlias for use in tests.
func ExtractCVEAlias(aliases, euvdId string) string {
	return extractCVEAlias(aliases, euvdId)
}

// EuvdItemToEntryTest is a test helper that constructs an euvdItem and calls euvdItemToEntry.
// This allows unit tests to verify conversion logic without network access.
func EuvdItemToEntryTest(depName, productName string, baseScore float64, baseScoreVersion, aliases, euvdId, exploitedSince string) (CVEEntry, bool) {
	item := euvdItem{
		ID:               euvdId,
		BaseScore:        baseScore,
		BaseScoreVersion: baseScoreVersion,
		Aliases:          aliases,
		ExploitedSince:   exploitedSince,
		Products: []euvdProductEntry{
			{Product: struct {
				Name string `json:"name"`
			}{Name: productName}},
		},
	}
	return euvdItemToEntry(item, depName)
}

// EnrichFromEUVD looks up a CVE in [EUVD] by its CVE identifier and returns a CVEEntry
// with [EUVD]-specific metadata: EUVD ID, CVSS score, and exploited flag. The product name
// filter is intentionally NOT applied here - OSV has already confirmed the package match;
// [EUVD] is used solely as a metadata enrichment source.
func EnrichFromEUVD(dep Dependency, cveID string) (CVEEntry, bool) {
	apiURL := EUVD_API_BASE + "/enisaid?id=" + url.QueryEscape(cveID)
	client := &http.Client{Timeout: EUVD_HTTP_TIMEOUT}
	resp, err := client.Get(apiURL)
	if err != nil {
		log.Printf("[WARN] EUVD enrich %s: %v", cveID, err)
		return CVEEntry{}, false
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return CVEEntry{}, false
	}

	var item euvdItem
	// Use json.NewDecoder to read only the first JSON object.
	// EUVD /enisaid responses may contain additional concatenated objects.
	if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
		log.Printf("[WARN] EUVD enrich %s parse: %v", cveID, err)
		return CVEEntry{}, false
	}
	if item.ID == "" {
		return CVEEntry{}, false
	}

	method := "CVSSv31"
	if item.BaseScoreVersion == "4.0" {
		method = "CVSSv40"
	}

	return CVEEntry{
		ID:          cveID,
		EuvdID:      item.ID,
		Package:     strings.ToLower(dep.Name),
		Severity:    normalizeCVSS(item.BaseScore),
		CVSS:        item.BaseScore,
		Description: item.Description,
		ScoreMethod: method,
		Exploited:   item.ExploitedSince != "",
		Source:      "OSV+EUVD",
	}, true
}

// MatchLive discovers and enriches vulnerabilities using OSV.dev and EUVD.
// It matches packages via OSV and enriches findings with EUVD metadata.
func MatchLive(deps []Dependency) ([]Finding, EuvdSnapshot, error) {
	snap, err := GetSnapshot()
	if err != nil {
		log.Printf("[WARN] EUVD snapshot failed: %v - continuing without snapshot ID", err)
		snap = EuvdSnapshot{
			ScanTimestamp: time.Now().UTC().Format(time.RFC3339),
			Source:        "OSV+EUVD (ENISA)",
		}
	}

	// seen key: "<depName>|<version>|<cveID>" - dedup per (component version, vulnerability)
	seen := make(map[string]bool)
	var findings []Finding

	for _, dep := range deps {
		vulns, err := QueryOSV(dep)
		if err != nil {
			log.Printf("[WARN] OSV query %q: %v", dep.Name, err)
			continue
		}
		for _, osv := range vulns {
			cveID := ExtractCVEFromOSV(osv)
			key := dep.Name + "|" + dep.Version + "|" + cveID
			if seen[key] {
				continue
			}
			seen[key] = true

			// Enrich with EUVD for CRA-compliant EU identifier.
			entry, inEUVD := EnrichFromEUVD(dep, cveID)
			if !inEUVD {
				// CVE not yet in EUVD - report OSV-only finding.
				score := osvSeverityToFloat(osv.DatabaseSpecific.Severity)
				entry = CVEEntry{
					ID:          cveID,
					Package:     strings.ToLower(dep.Name),
					Severity:    normalizeCVSS(score),
					CVSS:        score,
					Description: osv.Details,
					ScoreMethod: "CVSSv31",
					Source:      "OSV",
				}
			}

			findings = append(findings, Finding{
				CVE:       entry,
				Component: dep.Name,
				Version:   dep.Version,
			})
			log.Printf("[WARN] %s (EUVD: %s) CVSS %.1f %s in %s@%s exploited=%v source=%s",
				entry.ID, entry.EuvdID, entry.CVSS, entry.Severity,
				dep.Name, dep.Version, entry.Exploited, entry.Source)
		}
	}

	log.Printf("[INFO] Live scan: %d findings, latest EUVD=%s", len(findings), snap.LastEuvdId)
	return findings, snap, nil
}
