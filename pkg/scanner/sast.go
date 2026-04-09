package scanner

import (
	"bufio"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// SASTRule represents a static analysis pattern.
type SASTRule struct {
	ID          string
	Name        string
	Description string
	Severity    string
	CWEs        []int
	Extensions  []string // e.g., ".go", ".c", ".sh", or "*" for all
	Pattern     *regexp.Regexp
}

// Finding represents a vulnerability found in the codebase.
type Finding struct {
	ID          string
	ToolName    string
	RuleID      string
	Description string
	File        string
	Line        int
	Severity    string
	CWEs        []int
}

// RunSAST scans the root directory for security vulnerabilities.
// It skips binaries, hidden files, and patterns in .gitignore.
func RunSAST(root string, workers int, extraRules []SASTRule) []Finding {
	log.Printf("[INFO] Starting native SAST engine...")
	rules := GetEmbeddedRules()
	if len(extraRules) > 0 {
		rules = append(rules, extraRules...)
	}

	extRules := make(map[string][]SASTRule)
	var anyRules []SASTRule
	for _, r := range rules {
		for _, ext := range r.Extensions {
			if ext == "*" {
				anyRules = append(anyRules, r)
			} else {
				extRules[ext] = append(extRules[ext], r)
			}
		}
	}

	// Load .gitignore patterns
	ignorePatterns := loadGitignore(root)

	var files []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		
		// Check if path should be ignored
		relPath, _ := filepath.Rel(root, path)
		if shouldIgnorePath(relPath, ignorePatterns) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		
		name := info.Name()
		if info.IsDir() {
			// Skip hidden directories
			if strings.HasPrefix(name, ".") && name != "." && name != ".." {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip hidden files
		if strings.HasPrefix(name, ".") {
			return nil
		}

		// Skip large files (> 5MB)
		if info.Size() > 5*1024*1024 {
			return nil
		}

		// Skip known binary extensions
		ext := strings.ToLower(filepath.Ext(name))
		if isBinaryExt(ext) {
			return nil
		}
		
		// For wildcard rules, only scan interesting text files
		if len(anyRules) > 0 {
			if isInterestingTextFile(ext) {
				files = append(files, path)
				return nil
			}
		}

		if len(extRules[ext]) > 0 {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		log.Printf("[WARN] SAST walk failed: %v", err)
	}

	totalFiles := len(files)
	log.Printf("[INFO] SAST: found %d source files", totalFiles)

	jobCh := make(chan string, totalFiles)
	for _, f := range files {
		jobCh <- f
	}
	close(jobCh)

	var mu sync.Mutex
	var findings []Finding
	var wg sync.WaitGroup
	var scanned int

	if workers < 1 {
		workers = 12
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobCh {
				ext := filepath.Ext(path)
				activeRules := append([]SASTRule{}, anyRules...)
				activeRules = append(activeRules, extRules[ext]...)

				if len(activeRules) == 0 {
					continue
				}

				fileFindings := scanFile(path, activeRules)
				
				mu.Lock()
				scanned++
				if scanned%100 == 0 || scanned == totalFiles {
					log.Printf("[INFO] SAST progress: %d/%d files scanned", scanned, totalFiles)
				}
				if len(fileFindings) > 0 {
					findings = append(findings, fileFindings...)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	log.Printf("[INFO] Native SAST completed: found %d issues", len(findings))
	return findings
}

func scanFile(path string, rules []SASTRule) []Finding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []Finding
	scanner := bufio.NewScanner(f)
	lineNum := 1

	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 2048 { // Skip minified/huge lines to prevent regex lockup
			lineNum++
			continue
		}

		// Skip comment-only lines to reduce false positives
		trimmed := strings.TrimSpace(line)
		if isCommentLine(trimmed, path) {
			lineNum++
			continue
		}

		for _, rule := range rules {
			if rule.Pattern.MatchString(line) {
				// Only report CRITICAL and HIGH severity to avoid false positive noise
				if rule.Severity != "critical" && rule.Severity != "high" {
					continue
				}
				
				findings = append(findings, Finding{
					ToolName:    "EUChainGuard-Native-SAST",
					RuleID:      rule.ID,
					Description: rule.Name + ": " + rule.Description,
					File:        path,
					Line:        lineNum,
					Severity:    rule.Severity,
					CWEs:        rule.CWEs,
				})
			}
		}
		lineNum++
	}
	return findings
}

// isCommentLine checks if a line is a comment.
func isCommentLine(line, path string) bool {
	if line == "" {
		return true
	}

	ext := strings.ToLower(filepath.Ext(path))
	
	// Go, C, C++, Java, C#, TypeScript, JavaScript
	if ext == ".go" || ext == ".c" || ext == ".cpp" || ext == ".h" || 
	   ext == ".hpp" || ext == ".java" || ext == ".cs" || ext == ".js" || 
	   ext == ".ts" || ext == ".tsx" || ext == ".jsx" {
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			return true
		}
	}
	
	// Python, Bash, Shell
	if ext == ".py" || ext == ".sh" || ext == ".bash" || ext == ".zsh" {
		if strings.HasPrefix(line, "#") {
			return true
		}
	}
	
	return false
}

// loadGitignore reads the .gitignore file.
func loadGitignore(root string) map[string]bool {
	patterns := make(map[string]bool)

	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		return patterns
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns[line] = true
	}

	return patterns
}

// shouldIgnorePath checks if a relative path matches gitignore patterns.
func shouldIgnorePath(relPath string, patterns map[string]bool) bool {
	if len(patterns) == 0 {
		return false
	}

	relPath = filepath.ToSlash(relPath)
	parts := strings.Split(relPath, "/")

	for pattern := range patterns {
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			continue
		}

		pattern = strings.TrimSuffix(pattern, "/")

		// Exact match at first level
		if pattern == parts[0] {
			return true
		}

		// Match as directory segment
		for _, part := range parts {
			if part == pattern {
				return true
			}
		}

		// Glob match
		if strings.Contains(pattern, "*") {
			if matched, _ := filepath.Match(pattern, filepath.Base(relPath)); matched {
				return true
			}
		}
	}

	return false
}

func isBinaryExt(ext string) bool {
	binaries := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".obj": true, ".o": true, ".a": true,
		".lib": true, ".pyc": true, ".pyo": true, ".pyd": true,
		".class": true, ".jar": true, ".war": true, ".ear": true,
		".zip": true, ".tar": true, ".gz": true, ".7z": true, ".rar": true, ".bz2": true, ".xz": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true, ".ico": true, ".tiff": true, ".bmp": true,
		".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true,
		".odt": true, ".ods": true, ".odp": true,
		".mp3": true, ".mp4": true, ".wav": true, ".mov": true, ".avi": true, ".mkv": true, ".webm": true,
		".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
		".wasm": true, ".db": true, ".sqlite": true, ".sqlite3": true,
	}
	return binaries[ext]
}

func isInterestingTextFile(ext string) bool {
	// If no extension, could be a script or a README, etc.
	if ext == "" {
		return true
	}
	textExts := map[string]bool{
		".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".c": true, ".cpp": true, ".h": true, ".hpp": true, ".cs": true, ".java": true,
		".rb": true, ".php": true, ".sh": true, ".bash": true, ".zsh": true, ".ps1": true,
		".env": true, ".yml": true, ".yaml": true, ".json": true, ".xml": true,
		".txt": true, ".md": true, ".sql": true, ".ini": true, ".conf": true, ".toml": true,
		".dockerfile": true, ".makefile": true, ".gradle": true, ".properties": true,
		".html": true, ".htm": true, ".xhtml": true,
	}
	return textExts[ext]
}

