package gateway

import "encoding/json"

// marshalJSON is a named indirection so that [Capabilities.MarshalJSON] does not
// look like it is recursing into itself.
func marshalJSON(v any) ([]byte, error) { return json.Marshal(v) }
