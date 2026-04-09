package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
)

// packageJSON is the minimal structure of a Node.js package.json file.
type packageJSON struct {
	Name             string            `json:"name"`
	Version          string            `json:"version"`
	Dependencies     map[string]string `json:"dependencies"`
	DevDependencies  map[string]string `json:"devDependencies"`
	PeerDependencies map[string]string `json:"peerDependencies"`
	License          string            `json:"license"`
}

// ParsePackageJSON extracts dependencies from a package.json file.
// It includes dependencies, devDependencies, and peerDependencies sections.
func ParsePackageJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParsePackageJSON read %w: %s", err, path)
	}

	var pkg packageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("scanner.ParsePackageJSON parse %w", err)
	}

	var deps []Dependency

	// Runtime dependencies (direct)
	for name, ver := range pkg.Dependencies {
		deps = append(deps, makePkgDep(name, ver, pkg.License, true, false))
	}

	// Dev dependencies - not required for runtime; CRA optional scope
	for name, ver := range pkg.DevDependencies {
		deps = append(deps, makePkgDep(name, ver, "", false, true))
	}

	// Peer dependencies
	for name, ver := range pkg.PeerDependencies {
		deps = append(deps, makePkgDep(name, ver, "", false, false))
	}

	log.Printf("[INFO] ParsePackageJSON %s: %d deps", path, len(deps))
	return deps, nil
}

// pkgLock is the structure of package-lock.json (supports v1, v2, v3).
type pkgLock struct {
	LockfileVersion int `json:"lockfileVersion"`
	// v2/v3 format: packages map keyed as "node_modules/name"
	Packages map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"packages"`
	// v1 format: dependencies map keyed by package name
	Dependencies map[string]struct {
		Version string `json:"version"`
		Dev     bool   `json:"dev"`
	} `json:"dependencies"`
}

// ParsePackageLockJSON extracts dependencies from package-lock.json.
// It supports lockfile versions 1, 2, and 3.
func ParsePackageLockJSON(path string) ([]Dependency, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParsePackageLockJSON read %w: %s", err, path)
	}

	var lock pkgLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return nil, fmt.Errorf("scanner.ParsePackageLockJSON parse %w", err)
	}

	var deps []Dependency

	if lock.LockfileVersion >= 2 && len(lock.Packages) > 0 {
		for key, pkg := range lock.Packages {
			if key == "" || pkg.Version == "" {
				continue
			}
			// Key format: "node_modules/name" or nested "node_modules/a/node_modules/b"
			name := key
			if idx := strings.LastIndex(key, "node_modules/"); idx >= 0 {
				name = key[idx+len("node_modules/"):]
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "npm",
				Direct:    false,
				PURL:      BuildPURL("npm", name, pkg.Version),
			})
		}
	} else {
		// v1 format
		for name, dep := range lock.Dependencies {
			if dep.Version == "" {
				continue
			}
			deps = append(deps, Dependency{
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				Direct:    false,
				PURL:      BuildPURL("npm", name, dep.Version),
			})
		}
	}

	log.Printf("[INFO] ParsePackageLockJSON %s: %d deps", path, len(deps))
	return deps, nil
}

// ParseYarnLock extracts dependencies from a yarn.lock file (v1 classic).
func ParseYarnLock(path string) ([]Dependency, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scanner.ParseYarnLock open %w: %s", err, path)
	}
	defer f.Close()

	seen := make(map[string]bool)
	var deps []Dependency
	var curName string
	sc := bufio.NewScanner(f)

	for sc.Scan() {
		line := sc.Text()

		// Skip comments and blank lines
		if strings.HasPrefix(strings.TrimSpace(line), "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Entry header: `"package@range", "package@range":` or `package@range:`
		// Extract package name from the first specifier
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			entry := strings.TrimSuffix(trimmed, ":")
			// May be quoted or bare, may have multiple specifiers separated by ", "
			entry = strings.Trim(entry, "\"")
			parts := strings.SplitN(entry, ",", 2)
			spec := strings.TrimSpace(parts[0])
			spec = strings.Trim(spec, "\"")
			// name is everything before the last "@"
			if atIdx := strings.LastIndex(spec, "@"); atIdx > 0 {
				curName = spec[:atIdx]
			} else {
				curName = spec
			}
			continue
		}

		// Version line: `  version "x.y.z"`
		if strings.Contains(line, "version") && strings.Contains(line, "\"") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[0] == "version" && curName != "" {
				version := strings.Trim(fields[1], "\"")
				key := curName + "@" + version
				if !seen[key] {
					seen[key] = true
					deps = append(deps, Dependency{
						Name:      curName,
						Version:   version,
						Ecosystem: "npm",
						Direct:    false,
						PURL:      BuildPURL("npm", curName, version),
					})
				}
				curName = ""
			}
		}
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scanner.ParseYarnLock scan %w", err)
	}

	log.Printf("[INFO] ParseYarnLock %s: %d deps", path, len(deps))
	return deps, nil
}

// makePkgDep constructs a Dependency with populated [PURL] from npm package metadata.
func makePkgDep(name, version, license string, direct, dev bool) Dependency {
	// Normalise version: strip semver range operators for PURL
	cleanVer := strings.TrimLeft(version, "^~>=<")
	return Dependency{
		Name:      name,
		Version:   cleanVer,
		Ecosystem: "npm",
		PURL:      BuildPURL("npm", name, cleanVer),
		License:   license,
		Direct:    direct,
		Dev:       dev,
	}
}
