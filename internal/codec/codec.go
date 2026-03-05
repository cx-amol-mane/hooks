// Package codec handles JSON serialization between hook processes and AI agents.
// Hooks receive context via stdin (JSON) and respond via stdout (JSON).
package codec

import (
	"encoding/json"
	"os"
)

// DecodeStdin decodes one JSON object from stdin.
// Uses json.Decoder instead of io.ReadAll so it returns as soon as a
// complete JSON value is read, without waiting for EOF. This is critical
// for Cursor, which writes JSON to the pipe but does NOT close it.
func DecodeStdin(v any) error {
	return json.NewDecoder(os.Stdin).Decode(v)
}

// EncodeStdout marshals v to JSON and writes it to stdout followed by a newline.
func EncodeStdout(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}
