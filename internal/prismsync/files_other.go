//go:build !unix

package prismsync

import "os"

// The fleet's native snapshot transport requires Unix ownership semantics.
func privateOwner(os.FileInfo) bool { return false }
