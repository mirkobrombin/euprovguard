package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// vcpkgManifest is the structure of a vcpkg.json file.
type vcpkgManifest struct {
	Dependencies []json.RawMessage `json:"dependencies"`
}

// ParseVcpkgJSON extracts direct dependencies from a vcpkg.json manifest file.
// Each dependency may be a plain string or an object with a "name" field.
// Returns dependencies with Name, [PURL], Ecosystem="vcpkg", and Direct=true.
func ParseVcpkgJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseVcpkgJSON read %w: %s", err, path)
	}

	var manifest vcpkgManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("scanner.ParseVcpkgJSON parse %w", err)
	}

	var deps []Dependency
	for _, raw := range manifest.Dependencies {
		var name string
		var version string

		// Try string form: "openssl"
		var strDep string
		if json.Unmarshal(raw, &strDep) == nil {
			name = strDep
		} else {
			// Try object form: {"name": "openssl", "version": "3.0.0"}
			var objDep struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}
			if json.Unmarshal(raw, &objDep) == nil {
				name = objDep.Name
				version = objDep.Version
			}
		}

		if name == "" {
			continue
		}
		dep := Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "vcpkg",
			Direct:    true,
		}
		dep.PURL = BuildPURL("vcpkg", dep.Name, dep.Version)
		deps = append(deps, dep)
	}

	log.Printf("[INFO] ParseVcpkgJSON %s: %d deps", path, len(deps))
	return deps, nil
}

// vcpkgLock is the minimal structure of a vcpkg-lock.json file.
// The actual format stores packages under "overrides" and "packages" keys.
type vcpkgLock struct {
	// Packages is a map of port-name to version details (vcpkg-lock v1).
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// ParseVcpkgLock extracts the complete resolved dependency graph from vcpkg-lock.json.
// Returns dependencies with Name, Version, [PURL], Ecosystem="vcpkg", and Direct=false.
func ParseVcpkgLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseVcpkgLock read %w: %s", err, path)
	}

	var lock vcpkgLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("scanner.ParseVcpkgLock parse %w", err)
	}

	var deps []Dependency
	for name, pkg := range lock.Packages {
		dep := Dependency{
			Name:      name,
			Version:   pkg.Version,
			Ecosystem: "vcpkg",
			Direct:    false,
		}
		dep.PURL = BuildPURL("vcpkg", dep.Name, dep.Version)
		deps = append(deps, dep)
	}

	log.Printf("[INFO] ParseVcpkgLock %s: %d deps", path, len(deps))
	return deps, nil
}

// ParseConanfile extracts direct dependencies from a conanfile.txt file.
// It parses the [requires] section which contains entries in "name/version" format.
// Returns dependencies with Name, Version, [PURL], Ecosystem="conan", and Direct=true.
func ParseConanfile(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseConanfile open %w: %s", err, path)
	}
	defer f.Close()

	var deps []Dependency
	inRequires := false
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

		if strings.ToLower(line) == "[requires]" {
			inRequires = true
			continue
		}
		if strings.HasPrefix(line, "[") {
			inRequires = false
			continue
		}

		if !inRequires {
			continue
		}

		// Format: "openssl/1.1.1t" or "zlib/1.2.13@user/channel"
		// Strip channel suffix (@user/channel)
		if atIdx := strings.Index(line, "@"); atIdx >= 0 {
			line = line[:atIdx]
		}

		parts := strings.SplitN(line, "/", 2)
		name := strings.TrimSpace(parts[0])
		version := ""
		if len(parts) == 2 {
			version = strings.TrimSpace(parts[1])
		}

		if name == "" {
			continue
		}
		dep := Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "conan",
			Direct:    true,
		}
		dep.PURL = BuildPURL("conan", dep.Name, dep.Version)
		deps = append(deps, dep)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner.ParseConanfile scan %w", err)
	}

	log.Printf("[INFO] ParseConanfile %s: %d deps", path, len(deps))
	return deps, nil
}

// conanLock is the minimal structure of a conan.lock file (JSON format).
// The graph_lock.nodes map contains all resolved packages as "name/version#revision".
type conanLock struct {
	GraphLock struct {
		Nodes map[string]struct {
			Pref string `json:"pref"`
			Ref  string `json:"ref"`
		} `json:"nodes"`
	} `json:"graph_lock"`
}

// ParseConanLock extracts the complete resolved dependency graph from a conan.lock file.
// Returns dependencies with Name, Version, [PURL], Ecosystem="conan", and Direct=false.
func ParseConanLock(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseConanLock read %w: %s", err, path)
	}

	var lock conanLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("scanner.ParseConanLock parse %w", err)
	}

	seen := make(map[string]bool)
	var deps []Dependency

	for _, node := range lock.GraphLock.Nodes {
		// Use "pref" field first, fall back to "ref"
		ref := node.Pref
		if ref == "" {
			ref = node.Ref
		}
		if ref == "" {
			continue
		}

		// Format: "name/version#revision" or "name/version@user/channel#revision"
		// Strip @user/channel and #revision
		if atIdx := strings.Index(ref, "@"); atIdx >= 0 {
			ref = ref[:atIdx]
		}
		if hashIdx := strings.Index(ref, "#"); hashIdx >= 0 {
			ref = ref[:hashIdx]
		}

		parts := strings.SplitN(ref, "/", 2)
		name := strings.TrimSpace(parts[0])
		version := ""
		if len(parts) == 2 {
			version = strings.TrimSpace(parts[1])
		}

		if name == "" {
			continue
		}
		key := name + "@" + version
		if seen[key] {
			continue
		}
		seen[key] = true

		dep := Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "conan",
			Direct:    false,
		}
		dep.PURL = BuildPURL("conan", dep.Name, dep.Version)
		deps = append(deps, dep)
	}

	log.Printf("[INFO] ParseConanLock %s: %d deps", path, len(deps))
	return deps, nil
}
