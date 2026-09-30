// Package help prints privx-mcp-proxy usage text.
package help

import (
	_ "embed"
	"io"
	"strings"
)

//go:embed help.txt
var text string

// Text is the embedded --help document.
func Text() string {
	return text
}

// Fprint writes the help text to w.
func Fprint(w io.Writer) error {
	out := text
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}

	_, err := io.WriteString(w, out)

	return err
}
