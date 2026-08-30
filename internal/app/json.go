package app

import "encoding/json"

// marshal and unmarshal are named indirections so that the state-file code
// reads as "write the state" rather than as JSON plumbing, and so that changing
// the on-disk format later is one edit rather than a search.
func marshal(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

func unmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }
