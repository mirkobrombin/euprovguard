package scanner

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
)

// Dependency represents a single software dependency extracted from a manifest.
type Dependency struct {
	// Name is the package name as declared in the manifest.
	Name string
	// Version is the declared version string.
	Version string
	// Ecosystem is the package ecosystem: "go", "cargo", "npm", "pypi", "nuget", "vcpkg", "conan".
	Ecosystem string
	// PURL is the Package URL (https://github.com/package-url/purl-spec).
	PURL string
	// License is the declared license identifier (SPDX), if available.
	License string
	// Direct indicates whether this is a direct (true) or transitive (false) dependency.
	Direct bool
	// Dev indicates a development/test-only dependency (npm devDependencies, Rust dev-dependencies, etc.).
	// Dev deps are excluded from CRA compliance scope; CycloneDX scope becomes "optional".
	Dev bool
}

// BuildPURL constructs a [Package URL] for the given ecosystem, name, and version.
// It formats the PURL according to the Package URL specification.
func BuildPURL(ecosystem, name, version string) string {
	switch strings.ToLower(ecosystem) {
	case "go":
		return fmt.Sprintf("pkg:golang/%s@%s", name, version)
	case "cargo":
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	case "npm":
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	case "pypi":
		return fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(name), version)
	case "nuget":
		return fmt.Sprintf("pkg:nuget/%s@%s", name, version)
	case "conan":
		return fmt.Sprintf("pkg:conan/%s@%s", name, version)
	case "vcpkg":
		return fmt.Sprintf("pkg:generic/vcpkg/%s@%s", name, version)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", name, version)
	}
}

// ParseGoMod extracts dependencies from a go.mod file.
// It correctly marks indirect (transitive) dependencies using the "// indirect" annotation.
// In Go 1.17+, go.mod includes all transitive dependencies - both direct and indirect.
// Returns dependencies with [PURL], version, and Direct flag set appropriately.
func ParseGoMod(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseGoMod open %w: %s", err, path)
	}
	defer f.Close()

	var deps []Dependency
	inRequire := false
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		rawLine := strings.TrimSpace(sc.Text())

		// Check for "// indirect" BEFORE stripping comments - CRA requires accurate Direct flag.
		isIndirect := strings.Contains(rawLine, "// indirect")

		// Strip inline comments
		line := rawLine
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		if line == "" {
			continue
		}

		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(parts) >= 2 {
				dep := Dependency{
					Name:      parts[0],
					Version:   strings.TrimSuffix(parts[1], "+incompatible"),
					Ecosystem: "go",
					Direct:    !isIndirect,
				}
				dep.PURL = BuildPURL("go", dep.Name, dep.Version)
				deps = append(deps, dep)
			}
			continue
		}

		// Block require entry
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dep := Dependency{
					Name:      parts[0],
					Version:   strings.TrimSuffix(parts[1], "+incompatible"),
					Ecosystem: "go",
					Direct:    !isIndirect,
				}
				dep.PURL = BuildPURL("go", dep.Name, dep.Version)
				deps = append(deps, dep)
			}
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner.ParseGoMod scan %w", err)
	}

	log.Printf("[INFO] ParseGoMod %s: %d deps", path, len(deps))
	return deps, nil
}

// ParseGoSum extracts the complete transitive dependency graph from a go.sum file.
// go.sum contains checksums for all modules ever resolved (direct + transitive).
// Each module has two entries: one for source code (used here) and one for go.mod only (skipped).
// Returns dependencies with [PURL], Ecosystem="go", and Direct=false (set by mergeDeps for direct deps).
func ParseGoSum(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseGoSum open %w: %s", err, path)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var deps []Dependency
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) < 3 {
			continue
		}
		modPath := parts[0]
		rawVer := parts[1]

		// Skip go.mod-only checksum entries (no actual source code).
		if strings.Contains(rawVer, "/go.mod") {
			continue
		}

		version := strings.TrimSuffix(rawVer, "+incompatible")
		key := modPath + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		dep := Dependency{
			Name:      modPath,
			Version:   version,
			Ecosystem: "go",
			// Direct flag will be set to true by mergeDeps if this dep also appears in go.mod.
			Direct: false,
		}
		dep.PURL = BuildPURL("go", dep.Name, dep.Version)
		deps = append(deps, dep)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner.ParseGoSum scan %w", err)
	}

	log.Printf("[INFO] ParseGoSum %s: %d deps", path, len(deps))
	return deps, nil
}
