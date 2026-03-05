// Package codec handles JSON serialization between hook processes and AI agents.
// Hooks receive context via stdin (JSON) and respond via stdout (JSON).
package codec

import (
	"encoding/json"
	"io"
	"os"
)

// DecodeStdin reads all of stdin and unmarshals the JSON into v.
func DecodeStdin(v any) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// EncodeStdout marshals v to JSON and writes it to stdout followed by a newline.
func EncodeStdout(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}
