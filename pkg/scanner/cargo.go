package scanner

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// ParseCargoToml extracts dependencies from a Cargo.toml file.
// It parses [dependencies], [dev-dependencies], and [build-dependencies] sections,
// marking dev-only dependencies appropriately. Returns dependencies with Name, Version,
// [PURL], and Ecosystem="cargo".
func ParseCargoToml(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseCargoToml open %w: %s", err, path)
	}
	defer f.Close()

	var deps []Dependency
	inDeps := false
	isDev := false
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		// Strip comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}

		// Detect relevant sections
		lower := strings.ToLower(line)
		if lower == "[dependencies]" || lower == "[build-dependencies]" {
			inDeps = true
			isDev = false
			continue
		}
		if lower == "[dev-dependencies]" {
			inDeps = true
			isDev = true
			continue
		}

		// Any other [section] ends dependency parsing
		if strings.HasPrefix(line, "[") {
			inDeps = false
			isDev = false
			continue
		}

		if !inDeps {
			continue
		}

		// Simple: name = "version"
		// Extended: name = { version = "x", features = [...] }
		eqIdx := strings.Index(line, "=")
		if eqIdx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:eqIdx])
		rest := strings.TrimSpace(line[eqIdx+1:])

		version := ""
		if strings.HasPrefix(rest, "\"") {
			// Simple string version
			version = strings.Trim(rest, "\"")
		} else if strings.HasPrefix(rest, "{") {
			// Inline table: extract version = "..."
			version = extractInlineVersion(rest)
		}

		if name == "" {
			continue
		}

		dep := Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "cargo",
			Direct:    !isDev,
			Dev:       isDev,
		}
		dep.PURL = BuildPURL("cargo", dep.Name, dep.Version)
		deps = append(deps, dep)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner.ParseCargoToml scan %w", err)
	}

	log.Printf("[INFO] ParseCargoToml %s: %d deps", path, len(deps))
	return deps, nil
}

// ParseCargoLock extracts the complete dependency graph from a Cargo.lock file.
// Cargo.lock uses [[package]] sections and contains all transitive dependencies
// resolved by Cargo, not just the direct ones from Cargo.toml. Returns dependencies
// with Name, Version, [PURL], Ecosystem="cargo", and Direct=false.
func ParseCargoLock(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseCargoLock open %w: %s", err, path)
	}
	defer f.Close()

	var deps []Dependency
	var curName, curVer string
	sc := bufio.NewScanner(f)

	flush := func() {
		if curName == "" {
			return
		}
		dep := Dependency{
			Name:      curName,
			Version:   curVer,
			Ecosystem: "cargo",
			// Direct flag will be set by mergeDeps for entries also in Cargo.toml.
			Direct: false,
		}
		dep.PURL = BuildPURL("cargo", dep.Name, dep.Version)
		deps = append(deps, dep)
		curName, curVer = "", ""
	}

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		if line == "[[package]]" {
			flush()
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			curName = strings.Trim(strings.TrimPrefix(line, "name = "), "\"")
		} else if strings.HasPrefix(line, "version = ") {
			curVer = strings.Trim(strings.TrimPrefix(line, "version = "), "\"")
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner.ParseCargoLock scan %w", err)
	}

	log.Printf("[INFO] ParseCargoLock %s: %d deps", path, len(deps))
	return deps, nil
}

// extractInlineVersion parses a version value from a Cargo inline table string.
// Example input: `{ version = "1.0", features = ["serde"] }`. Returns the version string or empty string if not found.
func extractInlineVersion(inline string) string {
	// Find version = "..."
	lower := strings.ToLower(inline)
	idx := strings.Index(lower, "version")
	if idx < 0 {
		return ""
	}
	sub := inline[idx:]
	eqIdx := strings.Index(sub, "=")
	if eqIdx < 0 {
		return ""
	}
	sub = strings.TrimSpace(sub[eqIdx+1:])
	if strings.HasPrefix(sub, "\"") {
		end := strings.Index(sub[1:], "\"")
		if end >= 0 {
			return sub[1 : end+1]
		}
	}
	return ""
}
