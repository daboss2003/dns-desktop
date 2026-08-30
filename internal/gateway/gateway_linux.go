//go:build linux

package gateway

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// New returns the gateway for this platform.
//
// Linux is the platform that can do all of it: an access point through hostapd,
// routing and masquerading through nftables, DNS capture by redirect, and
// per-device blocking. Everything above the two seams below — the command
// runner and the two probes — is in linux_session.go with no build tag, so the
// bring-up, the teardown and the recovery are tested on every machine that runs
// the test suite rather than only on one with a radio in it.
func New() Gateway {
	return &linuxGateway{
		run:          execRunner{},
		journal:      journal{dir: linuxRunDir},
		runDir:       linuxRunDir,
		defaultRoute: linuxDefaultRoute,
		wireless:     linuxWireless,
	}
}

// linuxRunDir is under /run, which is a memory file system: a reboot is
// therefore already a complete cleanup, and the only crash this has to recover
// from is a process death without one. It also means a hostapd configuration
// holding a pairwise master key never touches a disk.
const linuxRunDir = "/run/gatewaydns"

// execRunner is the only part of the Linux gateway that actually runs anything.
type execRunner struct{}

func (execRunner) Run(ctx context.Context, name, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// The command's own output, because "exit status 1" from nft is not a
		// diagnosis and its stderr always is.
		msg := strings.TrimSpace(string(out))
		if msg != "" {
			return string(out), errors.New(msg)
		}
	}
	return string(out), err
}

func (execRunner) Look(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// linuxDefaultRoute reads the routing table from /proc.
//
// From the file rather than by running `ip route`, because the file is a kernel
// interface with a fixed format and `ip` is a package that may not be
// installed. The destination and mask are both zero on the default route, and
// the flags must say the route is up.
func linuxDefaultRoute() (string, error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", err
	}
	defer f.Close()

	const (
		fieldIface = 0
		fieldDest  = 1
		fieldFlags = 3
		fieldMask  = 7
		rtfUp      = 0x0001
	)
	sc := bufio.NewScanner(f)
	sc.Scan() // the header
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) <= fieldMask {
			continue
		}
		if fields[fieldDest] != "00000000" || fields[fieldMask] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(fields[fieldFlags], 16, 32)
		if err != nil || flags&rtfUp == 0 {
			continue
		}
		return fields[fieldIface], nil
	}
	return "", errNoDefaultRoute
}

// linuxWireless reports whether an interface is wireless, and whether it can
// host an access point.
//
// The wireless test is the presence of /sys/class/net/<name>/wireless, which
// the kernel creates for every cfg80211 device and which needs no tools and no
// privileges.
//
// Whether the driver supports AP mode cannot be read from sysfs — it lives in
// the nl80211 interface-combination attributes, over generic netlink — so this
// build reports it as unknown with a reason rather than guessing. Guessing
// optimistically produces a hotspot that fails to start with a driver error;
// guessing pessimistically hides a feature the machine has.
func linuxWireless(name string) (bool, apSupport) {
	if _, err := os.Stat("/sys/class/net/" + name + "/wireless"); err != nil {
		if _, err := os.Stat("/sys/class/net/" + name + "/phy80211"); err != nil {
			return false, apSupport{}
		}
	}
	return true, apSupport{reason: "whether this adapter's driver supports access-point mode " +
		"is not determined in this build"}
}
