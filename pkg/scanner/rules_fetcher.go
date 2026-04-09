package scanner

import (
	"archive/tar"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CRS_ATOM_FEED is the URL for the OWASP Core Rule Set releases Atom feed.
const CRS_ATOM_FEED = "https://github.com/coreruleset/coreruleset/releases.atom"

// CRS_HTTP_TIMEOUT is the timeout for CRS download operations.
const CRS_HTTP_TIMEOUT = 30 * time.Second

// Feed represents the GitHub releases Atom feed.
type Feed struct {
	Entries []Entry `xml:"entry"`
}

// Entry represents a single release entry in the feed.
type Entry struct {
	ID    string `xml:"id"`
	Title string `xml:"title"`
	Link  Link   `xml:"link"`
}

// Link represents the link in the Atom entry.
type Link struct {
	Href string `xml:"href,attr"`
}

// FetchLatestCRS downloads the latest OWASP Core Rule Set from GitHub.
// It parses the Atom feed to find the latest release and downloads the minimal tar.gz.
func FetchLatestCRS(destDir string) error {
	client := &http.Client{Timeout: CRS_HTTP_TIMEOUT}

	log.Printf("[INFO] Fetching CRS Atom feed: %s", CRS_ATOM_FEED)
	resp, err := client.Get(CRS_ATOM_FEED)
	if err != nil {
		return fmt.Errorf("scanner.FetchLatestCRS: feed %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scanner.FetchLatestCRS: feed HTTP %d", resp.StatusCode)
	}

	var feed Feed
	if err := xml.NewDecoder(resp.Body).Decode(&feed); err != nil {
		return fmt.Errorf("scanner.FetchLatestCRS: decode xml %w", err)
	}

	if len(feed.Entries) == 0 {
		return fmt.Errorf("scanner.FetchLatestCRS: no releases found in feed")
	}

	// Latest release is the first entry
	latest := feed.Entries[0]
	version := extractVersion(latest.Title)
	log.Printf("[INFO] Latest CRS version identified: %s", version)

	// Construct download URL for the minimal tar.gz
	// Example: https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.10.0.tar.gz
	// Note: Minimal version might not be in the tag link, but we'll try the standard tag archive first.
	downloadURL := fmt.Sprintf("https://github.com/coreruleset/coreruleset/archive/refs/tags/%s.tar.gz", version)

	return downloadAndExtract(client, downloadURL, destDir)
}

func extractVersion(title string) string {
	// Title can be "v4.10.0" or "v4.25.0 (LTS)". 
	// We only want the first part (the actual tag).
	parts := strings.Fields(title)
	if len(parts) > 0 {
		return parts[0]
	}
	return strings.TrimSpace(title)
}

func downloadAndExtract(client *http.Client, url, destDir string) error {
	log.Printf("[INFO] Downloading CRS archive: %s", url)
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("scanner.downloadAndExtract: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("scanner.downloadAndExtract: HTTP %d", resp.StatusCode)
	}

	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("scanner.downloadAndExtract: mkdir %w", err)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("scanner.downloadAndExtract: gzip %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("scanner.downloadAndExtract: tar %w", err)
		}

		path := filepath.Join(destDir, header.Name)
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(path, 0755); err != nil {
				return fmt.Errorf("scanner.downloadAndExtract: mkdir entry %w", err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				return fmt.Errorf("scanner.downloadAndExtract: mkdir entry dir %w", err)
			}
			f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("scanner.downloadAndExtract: create file %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("scanner.downloadAndExtract: copy file %w", err)
			}
			f.Close()
		}
	}

	log.Printf("[INFO] CRS archive extracted to %s", destDir)
	return nil
}
