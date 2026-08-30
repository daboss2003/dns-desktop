package gateway

import "errors"

// errNoDefaultRoute reports that nothing currently carries the default route.
//
// It is not an error a caller sees: enumeration treats it as "no interface has
// it", because a machine that is unplugged or still associating is in a normal
// state and listing its interfaces should still work. [SelectUplink] is where
// the absence becomes a message, in terms of what to do about it.
var errNoDefaultRoute = errors.New("gateway: no default route")
