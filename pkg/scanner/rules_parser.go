package scanner

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ParseCRSRules traverses the extracted CRS directory and extracts regex patterns.
// It maps CRS SecRules to native SASTRule structs for the engine.
func ParseCRSRules(crsDir string) []SASTRule {
	log.Printf("[INFO] Parsing CRS rules from %s", crsDir)
	var rules []SASTRule

	// CRS rules are typically in the 'rules/' subdirectory
	rulesDir := ""
	err := filepath.Walk(crsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() && info.Name() == "rules" {
			rulesDir = path
			return filepath.SkipDir
		}
		return nil
	})

	if err != nil || rulesDir == "" {
		log.Printf("[WARN] CRS rules directory not found in %s", crsDir)
		return nil
	}

	err = filepath.Walk(rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".conf") {
			rules = append(rules, parseConfFile(path)...)
		}
		return nil
	})

	if err != nil {
		log.Printf("[WARN] Error walking CRS rules: %v", err)
	}

	log.Printf("[INFO] Parsed %d rules from CRS", len(rules))
	return rules
}

// parseConfFile extracts basic regex patterns from ModSecurity .conf files.
// This is a simplified parser focusing on SecRule patterns.
func parseConfFile(path string) []SASTRule {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var rules []SASTRule
	sc := bufio.NewScanner(f)
	filename := filepath.Base(path)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "SecRule") {
			continue
		}

		// Simplified extraction of patterns between quotes in SecRule
		// Example: SecRule REQUEST_URI "@rx \.bak$" "id:920100,..."
		re := regexp.MustCompile(`"@rx\s+([^"]+)"`)
		match := re.FindStringSubmatch(line)
		if len(match) < 2 {
			continue
		}

		rawPattern := match[1]
		pattern, err := regexp.Compile(rawPattern)
		if err != nil {
			continue
		}

		// Extract ID if available
		id := "CRS-" + filename
		idMatch := regexp.MustCompile(`id:(\d+)`).FindStringSubmatch(line)
		if len(idMatch) > 1 {
			id = "CRS-" + idMatch[1]
		}

		rules = append(rules, SASTRule{
			ID:          id,
			Name:        "CRS Pattern: " + filename,
			Description: "Pattern imported from OWASP Core Rule Set: " + line,
			Severity:    "medium",  // Default for CRS imports
			CWEs:        []int{20}, // Default to Input Validation
			Extensions:  []string{"*"},
			Pattern:     pattern,
		})
	}

	return rules
}
