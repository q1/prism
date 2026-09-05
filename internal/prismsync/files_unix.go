//go:build unix

package prismsync

import (
	"os"
	"syscall"
)

func privateOwner(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Getuid() && (info.IsDir() || stat.Nlink == 1)
}
