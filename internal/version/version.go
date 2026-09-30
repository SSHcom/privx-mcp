// Package version exposes build identity from the embedded version.json.
package version

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Product section names in version.json.
const (
	Server = "server"
	Proxy  = "proxy"
)

// Binary component names within each product section.
const (
	ServerBinary = "privx-mcp"
	ProxyBinary  = "privx-mcp-proxy"
)

//go:embed version.json
var raw []byte

type entry struct {
	name    string
	version string
}

var products map[string][]entry

func init() {
	decoded, err := decodeProducts(raw)
	if err != nil {
		panic("version: " + err.Error())
	}

	products = decoded
}

// Component returns the version string for name within product.
func Component(product, name string) (string, error) {
	entries, ok := products[product]
	if !ok {
		return "", fmt.Errorf("unknown product %q", product)
	}

	for _, e := range entries {
		if e.name == name {
			return e.version, nil
		}
	}

	return "", fmt.Errorf("unknown component %q in product %q", name, product)
}

// MustComponent is like Component but panics on error.
func MustComponent(product, name string) string {
	v, err := Component(product, name)
	if err != nil {
		panic("version: " + err.Error())
	}

	return v
}

// Lines returns "name version" strings for product, in version.json key order.
func Lines(product string) ([]string, error) {
	entries, ok := products[product]
	if !ok {
		return nil, fmt.Errorf("unknown product %q", product)
	}

	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.name+" "+e.version)
	}

	return out, nil
}

// Fprint writes Lines(product) to w, one line each, and a trailing newline after the last line.
func Fprint(w io.Writer, product string) error {
	lines, err := Lines(product)
	if err != nil {
		return err
	}

	_, err = io.WriteString(w, strings.Join(lines, "\n")+"\n")

	return err
}

func decodeProducts(data []byte) (map[string][]entry, error) {
	dec := json.NewDecoder(bytes.NewReader(data))

	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("decode version.json: %w", err)
	}

	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("version.json: want object, got %v", tok)
	}

	out := make(map[string][]entry)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("decode version.json: %w", err)
		}

		product, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("version.json: want string key, got %v", keyTok)
		}

		entries, err := decodeEntries(dec)
		if err != nil {
			return nil, fmt.Errorf("version.json product %q: %w", product, err)
		}

		out[product] = entries
	}

	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("decode version.json: %w", err)
	}

	return out, nil
}

func decodeEntries(dec *json.Decoder) ([]entry, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}

	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, fmt.Errorf("want object, got %v", tok)
	}

	var entries []entry

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}

		name, ok := keyTok.(string)
		if !ok {
			return nil, fmt.Errorf("want string key, got %v", keyTok)
		}

		valTok, err := dec.Token()
		if err != nil {
			return nil, err
		}

		ver, ok := valTok.(string)
		if !ok {
			return nil, fmt.Errorf("component %q: want string version, got %v", name, valTok)
		}

		entries = append(entries, entry{name: name, version: ver})
	}

	if _, err := dec.Token(); err != nil {
		return nil, err
	}

	return entries, nil
}
