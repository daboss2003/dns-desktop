// Package build reports what this binary is.
//
// It exists so that "which version is this?" has one answer, set at link time
// and recovered from the module's own build information when it was not. A
// binary that reports "unknown" because somebody ran `go build` instead of
// `make` is a binary whose bug reports cannot be acted on.
package build

import (
	"fmt"
	"runtime"
	"runtime/debug"
)

// Set at link time with -ldflags; see the Makefile.
var (
	version = ""
	commit  = ""
	date    = ""
)

// Info describes the running binary.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
	Go      string `json:"go"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Engine  string `json:"engine"`
}

// Current returns the build information.
//
// The engine's version is read from the module graph rather than stamped,
// because it is the one fact about this binary that the person who built it
// cannot get wrong by forgetting a flag — and "which engine version has this
// bug" is the first question a DNS defect raises.
func Current() Info {
	i := Info{
		Version: version,
		Commit:  commit,
		Date:    date,
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if i.Version == "" && bi.Main.Version != "" {
			i.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if i.Commit == "" {
					i.Commit = s.Value
				}
			case "vcs.time":
				if i.Date == "" {
					i.Date = s.Value
				}
			}
		}
		for _, d := range bi.Deps {
			if d.Path == enginePath {
				i.Engine = d.Version
				if d.Replace != nil {
					// A replace directive means a local checkout, which is the
					// development build. Saying so is more useful than
					// reporting the placeholder version it carries.
					i.Engine = d.Replace.Version + " (replaced by " + d.Replace.Path + ")"
				}
			}
		}
	}
	for _, p := range []*string{&i.Version, &i.Commit, &i.Date, &i.Engine} {
		if *p == "" {
			*p = "unknown"
		}
	}
	return i
}

const enginePath = "github.com/daboss2003/dns"

// String renders the information the way a --version flag should print it.
func (i Info) String() string {
	return fmt.Sprintf("gatewaydns-desktop %s\n  commit:   %s\n  built:    %s\n  engine:   %s\n  go:       %s\n  platform: %s/%s\n",
		i.Version, i.Commit, i.Date, i.Engine, i.Go, i.OS, i.Arch)
}
