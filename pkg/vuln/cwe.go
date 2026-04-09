package vuln

import (
	"encoding/xml"
	"fmt"
	"os"
)

// CWE_XML_URL is the official MITRE CWE XML feed.
const CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"

// WeaknessCatalog is the root element of the CWE XML.
type WeaknessCatalog struct {
	Name       string     `xml:"Name,attr"`
	Version    string     `xml:"Version,attr"`
	Date       string     `xml:"Date,attr"`
	Weaknesses []Weakness `xml:"Weaknesses>Weakness"`
}

// Weakness represents a single CWE entry.
type Weakness struct {
	ID          int    `xml:"ID,attr"`
	Name        string `xml:"Name,attr"`
	Description string `xml:"Description"`
}

// LoadCWEXML parses the extracted CWE XML file.
func LoadCWEXML(path string) (*WeaknessCatalog, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cat WeaknessCatalog
	if err := xml.NewDecoder(f).Decode(&cat); err != nil {
		return nil, fmt.Errorf("vuln.LoadCWEXML: decode %w", err)
	}
	return &cat, nil
}

// GetCWEEntry returns a map for fast lookup of CWE ID to Weakness info.
func GetCWEMap(cat *WeaknessCatalog) map[int]Weakness {
	m := make(map[int]Weakness)
	for _, w := range cat.Weaknesses {
		m[w.ID] = w
	}
	return m
}
