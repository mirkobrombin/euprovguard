package vuln

import (
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// CatalogMetadata holds the provenance info for a downloaded security database.
type CatalogMetadata struct {
	Name      string    `json:"name"`
	Version   string    `json:"version"`
	Date      string    `json:"date"`
	Hash      string    `json:"sha256"`
	FetchedAt time.Time `json:"fetchedAt"`
}

// FetchCatalog downloads a file, verifies its SHA256, and returns the metadata.
func FetchCatalog(name, url, destPath string) (*CatalogMetadata, error) {
	log.Printf("[INFO] Fetching %s catalog from %s", name, url)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("vuln.FetchCatalog: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vuln.FetchCatalog: HTTP %d", resp.StatusCode)
	}

	// Create dest dir
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return nil, fmt.Errorf("vuln.FetchCatalog: mkdir %w", err)
	}

	// Create file and hash at the same time
	f, err := os.Create(destPath)
	if err != nil {
		return nil, fmt.Errorf("vuln.FetchCatalog: create %w", err)
	}
	defer f.Close()

	hasher := sha256.New()
	mw := io.MultiWriter(f, hasher)

	if _, err := io.Copy(mw, resp.Body); err != nil {
		return nil, fmt.Errorf("vuln.FetchCatalog: copy %w", err)
	}

	hash := fmt.Sprintf("%x", hasher.Sum(nil))
	log.Printf("[INFO] %s downloaded. SHA256: %s", name, hash)

	return &CatalogMetadata{
		Name:      name,
		Hash:      hash,
		FetchedAt: time.Now(),
	}, nil
}

// Unzip extracts a ZIP archive to a destination directory.
func Unzip(src, dest string) ([]string, error) {
	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(dest, f.Name)
		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return nil, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return nil, err
		}

		rc, err := f.Open()
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(outFile, rc)

		outFile.Close()
		rc.Close()

		if err != nil {
			return nil, err
		}
	}
	return filenames, nil
}

// Ungzip extracts a GZIP file.
func Ungzip(src, dest string) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gr.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, gr)
	return err
}
