// Package device knows what is on the network and which policy applies to it.
//
// It is the join between two things the engine keeps deliberately apart: an
// address, which is all a DNS query carries, and a device, which is what a
// person sets a rule on. "No social media on the kids' tablet" is a sentence
// about a device; 192.168.4.37 is what arrives.
//
// # Identity
//
// A device has an opaque [ID] of this package's own making, and everything else
// about it — hardware address, hostname, current address — is an OBSERVATION
// that points at that identity rather than being it. That indirection is the
// whole design, and it is there because every observable signal is unstable in
// a different way:
//
//   - A hardware address is randomised by default on current iOS and Android.
//     The randomisation is per-network and persistent, so a phone keeps one
//     address on this network — which is why this works at all — but a device
//     reset, a "forget this network", or one of the rotating modes produces a
//     new one, and the same phone arrives as a stranger.
//   - A hostname is whatever somebody typed into a settings screen. It is not
//     unique, it is not stable, and it is chosen by the device rather than by
//     us, so it is a hint and a display string and never a key.
//   - An address is ours to assign and is stable while a lease holds, which is
//     what [dhcp.Pool] works to preserve — but it is not stable across a
//     re-addressing, and on a network where somebody else runs DHCP it is not
//     ours at all.
//
// So identity is assigned once and remembered, observations attach to it, and
// when a device does arrive as a stranger a person can merge the two. That is
// an admission that no automatic scheme is reliable, made in the design rather
// than discovered in the field.
//
// # The hot path
//
// [Table.Identify] runs on every DNS query, which on this hardware means tens
// of thousands a second. It reads an immutable index through an atomic pointer,
// so it takes no lock and blocks nothing, and every mutation builds a new index
// and swaps it — the same shape the engine's policy matcher uses, for the same
// reason.
//
// Learning is asynchronous. A query from an address nobody has seen is worth
// recording, and so is the fact that a known device is still here, but neither
// is worth a write on the query path: observations go onto a bounded channel
// and a single goroutine applies them. Past the bound they are dropped and
// counted, because a device appearing in the list a second late is a much
// smaller loss than a millisecond on every query.
//
// # Privacy
//
// This package knows which person in a household looked at what, more precisely
// than anything else in the product. It holds no query contents and no history
// — that is [storage]'s job and is separately gated — but the device list alone
// says who is home. It is kept in memory and persisted only where the caller
// puts it, and [Table.Forget] genuinely forgets.
package device

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gatewaydns/gatewaydns/clock"
	"github.com/gatewaydns/gatewaydns/resolver"

	"github.com/gatewaydns/gatewaydns-desktop/internal/dhcp"
)

// ID identifies a device for as long as it is known, across address changes and
// across a restart.
//
// It is opaque and generated, not derived from anything observable. A key
// derived from a hardware address would change when the address did, taking
// every rule set against it with it — which is the failure this indirection
// exists to prevent, and the one a user would describe as "the parental
// controls stopped working and I don't know when".
type ID string

// Source says how a device came to be known, which is what the UI shows when
// somebody asks why a device has no name.
type Source uint8

const (
	// SourceObserved is a device seen only because it sent a DNS query. It is
	// what a network where somebody else runs DHCP looks like, and it is the
	// difference between a device list and an empty screen.
	SourceObserved Source = iota
	// SourceDHCP is a device that took a lease from us, which is the only
	// moment it volunteers a hardware address, a hostname and a vendor class
	// in one packet.
	SourceDHCP
	// SourceManual is a device somebody entered by hand.
	SourceManual
)

func (s Source) String() string {
	switch s {
	case SourceDHCP:
		return "dhcp"
	case SourceManual:
		return "manual"
	default:
		return "observed"
	}
}

// Device is one thing on the network.
//
// It is a value, and [Table] hands out copies: a caller holds one, renders it
// and puts it in a JSON document without the table's state moving underneath.
type Device struct {
	ID ID `json:"id"`
	// Name is what a person calls it. It starts as the best guess available —
	// the DHCP hostname, or the address — and is overwritten the moment
	// somebody renames it, after which nothing discovered ever changes it
	// again. A device that renamed itself back to "android-a94f2" every time
	// it reconnected would be a device nobody could label.
	Name string `json:"name"`
	// NameSetByUser records that, and is why the rule above can be enforced.
	NameSetByUser bool `json:"name_set_by_user,omitempty"`

	// Profile names the policy profile applied to this device. Empty means the
	// default profile.
	Profile string `json:"profile,omitempty"`
	// Paused blocks every query from this device. It is the "off" switch a
	// person reaches for at bedtime, and it is deliberately not a profile:
	// it must be one click to set and one click to undo.
	Paused bool `json:"paused,omitempty"`

	// HWAddr is the hardware address last seen, and Hostname and Vendor are
	// what the device said about itself over DHCP. All three are untrusted
	// text or attacker-chosen bytes from a machine on the local network.
	HWAddr   string `json:"hwaddr,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Vendor   string `json:"vendor,omitempty"`

	// Addrs are the addresses currently mapped to this device, newest first.
	Addrs []netip.Addr `json:"addrs,omitempty"`

	Source    Source    `json:"-"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// DisplayName is the name to show, which is never empty.
func (d Device) DisplayName() string {
	switch {
	case d.Name != "":
		return d.Name
	case d.Hostname != "":
		return d.Hostname
	case len(d.Addrs) > 0:
		return d.Addrs[0].String()
	case d.HWAddr != "":
		return d.HWAddr
	default:
		return string(d.ID)
	}
}

// Options configure a [Table].
type Options struct {
	// MaxDevices bounds how many devices are remembered. Zero selects
	// [DefaultMaxDevices].
	//
	// It is a bound and not a hint: an address on a local network is
	// attacker-influenced, and a table that grew a device per spoofed source
	// address is a memory-exhaustion bug with a user interface. Past the bound
	// the least recently seen device is evicted, and evictions are counted so
	// that a full table is visible rather than merely quiet.
	MaxDevices int

	// SeenInterval is how often a query refreshes a device's LastSeen. Zero
	// selects [DefaultSeenInterval]. It exists so that "when was this device
	// last active" costs one write a minute rather than one per query.
	SeenInterval time.Duration

	// ObserveQueue bounds the learning channel. Zero selects
	// [DefaultObserveQueue].
	ObserveQueue int

	// OnChange is called after the table changes, with no lock held. It is how
	// a user interface learns to redraw and how state reaches disk. It must not
	// block for long and must not call back into the table.
	OnChange func()

	Clock clock.Clock
}

// Defaults for [Options].
const (
	// DefaultMaxDevices is generous for a household and small enough that a
	// full table is a few hundred kilobytes.
	DefaultMaxDevices = 4096
	// DefaultSeenInterval is a minute.
	DefaultSeenInterval = time.Minute
	// DefaultObserveQueue is deep enough to absorb a burst of new devices —
	// everything reconnecting after a router restart — without being deep
	// enough to matter if it is never drained.
	DefaultObserveQueue = 1024
)

// Errors from [Table].
var (
	// ErrUnknownDevice reports an ID the table does not hold.
	ErrUnknownDevice = errors.New("device: no such device")
	// ErrFull reports that the table is at [Options.MaxDevices].
	ErrFull = errors.New("device: the table is full")
)

// Table is the set of known devices and the index from address to device.
type Table struct {
	clk      clock.Clock
	max      int
	seenGap  time.Duration
	onChange func()

	// index is immutable once published. Identify reads it through this
	// pointer and takes no lock, which is what lets it run on the query path.
	index atomic.Pointer[index]

	mu      sync.Mutex
	devices map[ID]*Device
	byAddr  map[netip.Addr]ID
	byKey   map[string]ID // DHCP client key to device

	obs      chan observation
	dropped  atomic.Uint64
	evicted  atomic.Uint64
	quit     chan struct{}
	done     chan struct{}
	closed   atomic.Bool
	closeOne sync.Once
}

// index is the lock-free read path: address to identity, plus just enough to
// answer without touching the devices map.
type index struct {
	byAddr map[netip.Addr]entry
}

type entry struct {
	id       ID
	paused   bool
	profile  string
	lastSeen time.Time
}

type observation struct {
	addr netip.Addr
	at   time.Time
}

// New builds a table.
func New(opts Options) *Table {
	t := &Table{
		clk:      clock.OrSystem(opts.Clock),
		max:      orInt(opts.MaxDevices, DefaultMaxDevices),
		seenGap:  orDuration(opts.SeenInterval, DefaultSeenInterval),
		onChange: opts.OnChange,
		devices:  make(map[ID]*Device),
		byAddr:   make(map[netip.Addr]ID),
		byKey:    make(map[string]ID),
		obs:      make(chan observation, orInt(opts.ObserveQueue, DefaultObserveQueue)),
		quit:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	t.index.Store(&index{byAddr: map[netip.Addr]entry{}})
	go t.learn()
	return t
}

// Identify assigns a device identity to a client.
//
// This is the hook for [resolver.Options.Identify] and runs on every query. It
// takes no lock: one atomic load, one map read, and a bounded non-blocking send
// when there is something new to learn.
//
// A client whose address is unknown gets no identity and is passed through
// unchanged. It is not blocked and not delayed — a device the table has not
// caught up with yet must still resolve, or the first query after joining a
// network fails and the failure looks like the network being broken.
func (t *Table) Identify(c resolver.Client) resolver.Client {
	a := c.Addr.Addr()
	if !a.IsValid() {
		return c
	}
	a = a.Unmap()
	idx := t.index.Load()
	e, ok := idx.byAddr[a]
	if !ok {
		// New to us. Recorded asynchronously, because a write here would be a
		// write on the query path — and because an address that queries once
		// and never again should not cost more than a channel send that fails.
		t.observe(a)
		return c
	}
	c.ID = string(e.id)
	if t.clk.Now().Sub(e.lastSeen) >= t.seenGap {
		t.observe(a)
	}
	return c
}

// observe queues an address for the learner, or drops it.
func (t *Table) observe(a netip.Addr) {
	select {
	case t.obs <- observation{addr: a, at: t.clk.Now()}:
	default:
		// Dropped rather than blocked. A device appearing in the list a second
		// late is a much smaller loss than a millisecond on every query, and
		// the counter is what makes the loss visible rather than mysterious.
		t.dropped.Add(1)
	}
}

// learn applies queued observations.
func (t *Table) learn() {
	defer close(t.done)
	for {
		select {
		case <-t.quit:
			return
		case o := <-t.obs:
			t.applyObservation(o)
		}
	}
}

func (t *Table) applyObservation(o observation) {
	t.mu.Lock()
	changed := false
	if id, ok := t.byAddr[o.addr]; ok {
		if d := t.devices[id]; d != nil && o.at.After(d.LastSeen) {
			d.LastSeen = o.at
			changed = true
		}
	} else if d := t.newDeviceLocked(SourceObserved, o.at); d != nil {
		t.attachAddrLocked(d, o.addr)
		changed = true
	}
	if changed {
		t.publishLocked()
	}
	t.mu.Unlock()
	if changed {
		t.notify()
	}
}

// ObserveLease records what a DHCP lease told us.
//
// This is the richest observation available: the one moment a device
// volunteers a hardware address, a name and a vendor class together. It is
// wired to [dhcp.ServerOptions.OnBound], so it runs on the DHCP path — a
// handful of messages per device per lease period — and may therefore take the
// lock.
func (t *Table) ObserveLease(l dhcp.Lease) {
	if l.Key == "" || !l.Addr.IsValid() {
		return
	}
	now := t.clk.Now()

	t.mu.Lock()
	var d *Device
	if id, ok := t.byKey[l.Key]; ok {
		d = t.devices[id]
	}
	if d == nil {
		// An address we knew from OBSERVATION ALONE is the same device arriving
		// with its papers, and adopting that record keeps its history and any
		// name or profile already set against it.
		//
		// Only from observation. A record that has already identified itself —
		// one with a client key of its own — is a different device that used to
		// hold this address, and adopting it would hand the new device the old
		// one's identity, name and profile. That is the reused-address hazard
		// this whole package exists to avoid, and it is reachable here in the
		// most ordinary way there is: a tablet leaves, its lease lapses, and a
		// laptop is given the address next.
		if id, ok := t.byAddr[l.Addr.Unmap()]; ok {
			if cand := t.devices[id]; cand != nil && cand.Source == SourceObserved {
				d = cand
			}
		}
	}
	if d == nil {
		d = t.newDeviceLocked(SourceDHCP, now)
		if d == nil {
			t.mu.Unlock()
			return
		}
	}

	d.Source = SourceDHCP
	t.byKey[l.Key] = d.ID
	if len(l.HWAddr) > 0 {
		d.HWAddr = l.HWAddr.String()
	}
	if l.Hostname != "" {
		d.Hostname = l.Hostname
		// The discovered name fills in only while nobody has chosen one. A
		// device that renamed itself back to "android-a94f2" on every
		// reconnect would be a device nobody could label.
		if !d.NameSetByUser {
			d.Name = l.Hostname
		}
	}
	if !l.FirstSeen.IsZero() && (d.FirstSeen.IsZero() || l.FirstSeen.Before(d.FirstSeen)) {
		d.FirstSeen = l.FirstSeen
	}
	if now.After(d.LastSeen) {
		d.LastSeen = now
	}
	t.attachAddrLocked(d, l.Addr.Unmap())
	t.publishLocked()
	t.mu.Unlock()
	t.notify()
}

// newDeviceLocked creates and registers a device, evicting if it must.
func (t *Table) newDeviceLocked(src Source, now time.Time) *Device {
	if len(t.devices) >= t.max && !t.evictLocked() {
		return nil
	}
	d := &Device{ID: newID(), Source: src, FirstSeen: now, LastSeen: now}
	t.devices[d.ID] = d
	return d
}

// evictLocked drops the least recently seen device that nobody has customised.
//
// A device somebody named, paused or assigned a profile is never evicted: those
// are the records with a person's decision in them, and losing one silently
// turns off a rule they set. If every device is customised, the table refuses
// to grow instead — a full table is a visible problem, a forgotten rule is not.
func (t *Table) evictLocked() bool {
	var victim *Device
	for _, d := range t.devices {
		if d.NameSetByUser || d.Paused || d.Profile != "" {
			continue
		}
		if victim == nil || d.LastSeen.Before(victim.LastSeen) {
			victim = d
		}
	}
	if victim == nil {
		return false
	}
	t.removeLocked(victim.ID)
	t.evicted.Add(1)
	return true
}

func (t *Table) removeLocked(id ID) {
	for a, holder := range t.byAddr {
		if holder == id {
			delete(t.byAddr, a)
		}
	}
	for k, holder := range t.byKey {
		if holder == id {
			delete(t.byKey, k)
		}
	}
	delete(t.devices, id)
}

// attachAddrLocked points an address at a device, taking it from whoever had it.
//
// Taking it is the correct behaviour and the reason the index is authoritative:
// an address belongs to one device at a time, and a stale mapping is how the
// next device to take an address inherits the previous one's rules.
func (t *Table) attachAddrLocked(d *Device, a netip.Addr) {
	if prev, ok := t.byAddr[a]; ok && prev != d.ID {
		if old := t.devices[prev]; old != nil {
			old.Addrs = slices.DeleteFunc(old.Addrs, func(x netip.Addr) bool { return x == a })
		}
	}
	t.byAddr[a] = d.ID
	d.Addrs = slices.DeleteFunc(d.Addrs, func(x netip.Addr) bool { return x == a })
	d.Addrs = append([]netip.Addr{a}, d.Addrs...)
	const maxAddrs = 8
	if len(d.Addrs) > maxAddrs {
		for _, gone := range d.Addrs[maxAddrs:] {
			if t.byAddr[gone] == d.ID {
				delete(t.byAddr, gone)
			}
		}
		d.Addrs = d.Addrs[:maxAddrs]
	}
}

// publishLocked rebuilds the read index and swaps it in.
//
// A whole rebuild per change, which is a few thousand entries at most and
// happens on the DHCP path and on user actions — never on the query path. The
// alternative, mutating a shared map under a read lock, would put a lock on
// every query to save an allocation on an event that happens a few times an
// hour.
func (t *Table) publishLocked() {
	next := &index{byAddr: make(map[netip.Addr]entry, len(t.byAddr))}
	for a, id := range t.byAddr {
		d := t.devices[id]
		if d == nil {
			continue
		}
		next.byAddr[a] = entry{id: id, paused: d.Paused, profile: d.Profile, lastSeen: d.LastSeen}
	}
	t.index.Store(next)
}

func (t *Table) notify() {
	if t.onChange != nil {
		t.onChange()
	}
}

// Lookup returns the device at an address.
func (t *Table) Lookup(a netip.Addr) (Device, bool) {
	idx := t.index.Load()
	e, ok := idx.byAddr[a.Unmap()]
	if !ok {
		return Device{}, false
	}
	return t.Get(e.id)
}

// Get returns one device by identity.
func (t *Table) Get(id ID) (Device, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.devices[id]
	if !ok {
		return Device{}, false
	}
	return d.clone(), true
}

// Devices returns every known device, most recently seen first.
func (t *Table) Devices() []Device {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Device, 0, len(t.devices))
	for _, d := range t.devices {
		out = append(out, d.clone())
	}
	slices.SortFunc(out, func(a, b Device) int {
		if c := b.LastSeen.Compare(a.LastSeen); c != 0 {
			return c
		}
		return strings.Compare(string(a.ID), string(b.ID))
	})
	return out
}

// Rename sets the display name, and records that a person chose it.
func (t *Table) Rename(id ID, name string) error {
	name = SanitiseName(name)
	return t.update(id, func(d *Device) error {
		d.Name = name
		// Clearing the flag when the name is cleared, so that emptying the
		// field hands the device back to discovery rather than leaving it
		// permanently nameless.
		d.NameSetByUser = name != ""
		return nil
	})
}

// SetProfile assigns a policy profile. An empty name selects the default.
func (t *Table) SetProfile(id ID, profile string) error {
	return t.update(id, func(d *Device) error { d.Profile = profile; return nil })
}

// SetPaused blocks or unblocks every query from a device.
func (t *Table) SetPaused(id ID, paused bool) error {
	return t.update(id, func(d *Device) error { d.Paused = paused; return nil })
}

// Merge folds one device into another, keeping the target's name and profile.
//
// It exists because no automatic identity scheme is reliable: a phone that
// rotates its hardware address, or is reset, arrives as a stranger, and the
// only thing that knows the two are the same device is the person looking at
// the list. Without this the honest answer to "why are there two of my phone"
// would be "there is no way to fix that".
func (t *Table) Merge(into, from ID) error {
	if into == from {
		return errors.New("device: cannot merge a device into itself")
	}
	t.mu.Lock()
	target, ok := t.devices[into]
	if !ok {
		t.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknownDevice, into)
	}
	source, ok := t.devices[from]
	if !ok {
		t.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknownDevice, from)
	}

	if target.FirstSeen.IsZero() || (!source.FirstSeen.IsZero() && source.FirstSeen.Before(target.FirstSeen)) {
		target.FirstSeen = source.FirstSeen
	}
	if source.LastSeen.After(target.LastSeen) {
		target.LastSeen = source.LastSeen
	}
	if target.Hostname == "" {
		target.Hostname = source.Hostname
	}
	if target.HWAddr == "" {
		target.HWAddr = source.HWAddr
	}
	for k, holder := range t.byKey {
		if holder == from {
			t.byKey[k] = into
		}
	}
	for _, a := range source.Addrs {
		t.attachAddrLocked(target, a)
	}
	delete(t.devices, from)
	t.publishLocked()
	t.mu.Unlock()
	t.notify()
	return nil
}

// Forget removes a device and everything remembered about it.
//
// It genuinely forgets: the identity, the observations and the name all go, and
// the device reappears as a stranger if it comes back. That is the point — this
// is the deletion story for the most personal thing the product holds.
func (t *Table) Forget(id ID) error {
	t.mu.Lock()
	if _, ok := t.devices[id]; !ok {
		t.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknownDevice, id)
	}
	t.removeLocked(id)
	t.publishLocked()
	t.mu.Unlock()
	t.notify()
	return nil
}

func (t *Table) update(id ID, f func(*Device) error) error {
	t.mu.Lock()
	d, ok := t.devices[id]
	if !ok {
		t.mu.Unlock()
		return fmt.Errorf("%w: %s", ErrUnknownDevice, id)
	}
	if err := f(d); err != nil {
		t.mu.Unlock()
		return err
	}
	t.publishLocked()
	t.mu.Unlock()
	t.notify()
	return nil
}

// Add registers a device by hand, for one that will never speak DHCP.
func (t *Table) Add(name string, hw net.HardwareAddr, addrs ...netip.Addr) (Device, error) {
	now := t.clk.Now()
	t.mu.Lock()
	d := t.newDeviceLocked(SourceManual, now)
	if d == nil {
		t.mu.Unlock()
		return Device{}, ErrFull
	}
	d.Name = SanitiseName(name)
	d.NameSetByUser = d.Name != ""
	if len(hw) > 0 {
		d.HWAddr = hw.String()
		t.byKey["hw:"+string(hw)] = d.ID
	}
	for _, a := range addrs {
		if a.IsValid() {
			t.attachAddrLocked(d, a.Unmap())
		}
	}
	out := d.clone()
	t.publishLocked()
	t.mu.Unlock()
	t.notify()
	return out, nil
}

// Stats reports what the table holds and what it lost.
type Stats struct {
	Devices  int    `json:"devices"`
	Addrs    int    `json:"addrs"`
	Dropped  uint64 `json:"dropped"`
	Evicted  uint64 `json:"evicted"`
	Capacity int    `json:"capacity"`
}

// Stats returns a snapshot.
func (t *Table) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	return Stats{
		Devices:  len(t.devices),
		Addrs:    len(t.byAddr),
		Dropped:  t.dropped.Load(),
		Evicted:  t.evicted.Load(),
		Capacity: t.max,
	}
}

// State is the persistable form of a table.
type State struct {
	Version int      `json:"version"`
	Devices []Device `json:"devices"`
	// Keys maps DHCP client keys to devices. It is separate from Device
	// because a key is opaque bytes, and because one device may have several.
	Keys map[string]ID `json:"keys,omitempty"`
}

// Snapshot returns the table's state for persisting.
func (t *Table) Snapshot() State {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := State{Version: 1, Devices: make([]Device, 0, len(t.devices)), Keys: maps.Clone(t.byKey)}
	for _, d := range t.devices {
		s.Devices = append(s.Devices, d.clone())
	}
	slices.SortFunc(s.Devices, func(a, b Device) int { return strings.Compare(string(a.ID), string(b.ID)) })
	return s
}

// Restore replaces the table's contents.
//
// Addresses are restored along with the devices, which is deliberate: after a
// restart the leases are still held by the same devices, and a table that
// waited to relearn every address would apply the default profile to every
// device on the network for the first few queries after every restart. That is
// a filtering product briefly not filtering, which is the failure mode least
// acceptable here.
func (t *Table) Restore(s State) error {
	if s.Version != 1 {
		return fmt.Errorf("device: state version %d is not supported, want 1", s.Version)
	}
	t.mu.Lock()
	t.devices = make(map[ID]*Device, len(s.Devices))
	t.byAddr = make(map[netip.Addr]ID)
	t.byKey = make(map[string]ID, len(s.Keys))
	for i := range s.Devices {
		d := s.Devices[i]
		if d.ID == "" {
			continue
		}
		if len(t.devices) >= t.max {
			break
		}
		copied := d
		copied.Addrs = nil
		t.devices[d.ID] = &copied
		for _, a := range d.Addrs {
			if a.IsValid() {
				t.attachAddrLocked(&copied, a.Unmap())
			}
		}
	}
	for k, id := range s.Keys {
		if _, ok := t.devices[id]; ok {
			t.byKey[k] = id
		}
	}
	t.publishLocked()
	t.mu.Unlock()
	t.notify()
	return nil
}

// Close stops the learner. The table stays readable afterwards.
func (t *Table) Close() error {
	t.closeOne.Do(func() {
		t.closed.Store(true)
		close(t.quit)
		<-t.done
	})
	return nil
}

func (d *Device) clone() Device {
	out := *d
	out.Addrs = slices.Clone(d.Addrs)
	return out
}

// newID returns a fresh opaque identifier.
//
// From crypto/rand rather than a counter, so that an identifier carries no
// information about how many devices there are or in what order they appeared,
// and so that two tables merged by hand cannot collide.
func newID() ID {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on any supported platform; if it somehow
		// does, a duplicate identifier is far less bad than a dead resolver.
		return ID(fmt.Sprintf("dev-fallback-%d", time.Now().UnixNano()))
	}
	return ID("dev-" + hex.EncodeToString(b[:]))
}

// SanitiseName bounds and cleans a name for storage and display.
//
// Device names arrive from two places and neither is trusted: a DHCP hostname
// is chosen by a machine on the local network, and a typed name is chosen by a
// person who may paste anything. Both end up in a list, a log line and a JSON
// document.
func SanitiseName(s string) string {
	const maxName = 64
	var sb strings.Builder
	for _, r := range s {
		if sb.Len() >= maxName {
			break
		}
		if r == 0 {
			break
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		sb.WriteRune(r)
	}
	return strings.TrimSpace(sb.String())
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
