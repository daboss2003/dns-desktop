package device

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gatewaydns/gatewaydns/clock"
	"github.com/gatewaydns/gatewaydns/resolver"

	"github.com/gatewaydns/gatewaydns-desktop/internal/dhcp"
)

var epoch = time.Date(2026, 4, 1, 9, 0, 0, 0, time.UTC)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func client(s string) resolver.Client {
	return resolver.Client{Addr: netip.AddrPortFrom(addr(s), 41234), Transport: "udp"}
}

// newTable returns a table and a function that blocks until the learner has
// caught up. There is no sleeping anywhere in these tests: the table signals
// through OnChange, which is the same seam a user interface redraws on.
func newTable(t testing.TB, mutate func(*Options)) (*Table, *clock.Fake, func(int)) {
	t.Helper()
	fake := clock.NewFake(epoch)
	changes := make(chan struct{}, 256)
	opts := Options{
		Clock: fake,
		OnChange: func() {
			select {
			case changes <- struct{}{}:
			default:
			}
		},
	}
	if mutate != nil {
		mutate(&opts)
	}
	inner := opts.OnChange
	opts.OnChange = func() {
		if inner != nil {
			inner()
		}
	}
	tab := New(opts)
	t.Cleanup(func() { _ = tab.Close() })

	await := func(n int) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for range n {
			select {
			case <-changes:
			case <-deadline:
				t.Fatalf("the table did not settle: %+v", tab.Stats())
			}
		}
	}
	return tab, fake, await
}

func lease(a string, hw net.HardwareAddr, host string) dhcp.Lease {
	return dhcp.Lease{
		Key: "hw:" + string(hw), Addr: addr(a), HWAddr: hw, Hostname: host,
		FirstSeen: epoch, LastSeen: epoch,
	}
}

// A device that took a lease is identified on every query from its address, and
// the identity is what a per-device rule is written against.
func TestALeasedDeviceIsIdentified(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}

	tab.ObserveLease(lease("192.168.4.20", hw, "kids-tablet"))
	await(1)

	got := tab.Identify(client("192.168.4.20"))
	if got.ID == "" {
		t.Fatal("a leased device was not identified")
	}
	d, ok := tab.Get(ID(got.ID))
	if !ok {
		t.Fatal("the identity does not resolve to a device")
	}
	if d.Name != "kids-tablet" || d.HWAddr != hw.String() {
		t.Errorf("device = %+v", d)
	}
	if d.Source != SourceDHCP {
		t.Errorf("source = %v, want dhcp", d.Source)
	}
}

// A network where somebody else runs DHCP still has to show a device list, or
// the product's main screen is empty on a deployment where it only does DNS.
func TestAnUnknownAddressBecomesAnObservedDevice(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)

	// The first query is answered without waiting for anything: a device the
	// table has not caught up with must still resolve, or joining a network
	// looks broken.
	got := tab.Identify(client("192.168.4.55"))
	if got.ID != "" {
		t.Error("an unknown address was given an identity synchronously")
	}
	await(1)

	d, ok := tab.Lookup(addr("192.168.4.55"))
	if !ok {
		t.Fatal("the address was not learned")
	}
	if d.Source != SourceObserved {
		t.Errorf("source = %v, want observed", d.Source)
	}
	if d.DisplayName() != "192.168.4.55" {
		t.Errorf("display name = %q; an unnamed device must still be identifiable in a list", d.DisplayName())
	}
	// And the next query is identified.
	if tab.Identify(client("192.168.4.55")).ID == "" {
		t.Error("the second query from a learned address was not identified")
	}
}

// A device seen by DNS first and by DHCP second is one device. Adopting the
// existing record is what keeps a name and a profile somebody already set.
func TestADHCPLeaseAdoptsAnObservedDevice(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)

	tab.Identify(client("192.168.4.20"))
	await(1)
	first, _ := tab.Lookup(addr("192.168.4.20"))
	if err := tab.Rename(first.ID, "Sam's laptop"); err != nil {
		t.Fatal(err)
	}
	await(1)
	if err := tab.SetProfile(first.ID, "kids"); err != nil {
		t.Fatal(err)
	}
	await(1)

	tab.ObserveLease(lease("192.168.4.20", net.HardwareAddr{0x02, 0, 0, 0, 0, 9}, "android-a94f2"))
	await(1)

	if n := len(tab.Devices()); n != 1 {
		t.Errorf("%d devices, want 1: the lease should have adopted the observed record", n)
	}
	d, _ := tab.Lookup(addr("192.168.4.20"))
	if d.ID != first.ID {
		t.Errorf("identity changed from %s to %s; every rule set against it would have come off", first.ID, d.ID)
	}
	if d.Name != "Sam's laptop" {
		t.Errorf("name = %q, want the one a person chose", d.Name)
	}
	if d.Profile != "kids" {
		t.Errorf("profile = %q, want it kept", d.Profile)
	}
	if d.Hostname != "android-a94f2" {
		t.Errorf("hostname = %q, want the discovered one recorded", d.Hostname)
	}
}

// A device that renamed itself back to "android-a94f2" on every reconnect would
// be a device nobody could label.
func TestAChosenNameSurvivesDiscovery(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}

	tab.ObserveLease(lease("192.168.4.20", hw, "android-a94f2"))
	await(1)
	d, _ := tab.Lookup(addr("192.168.4.20"))
	if err := tab.Rename(d.ID, "Sam's phone"); err != nil {
		t.Fatal(err)
	}
	await(1)

	// It renews, still calling itself by its own name.
	tab.ObserveLease(lease("192.168.4.20", hw, "android-a94f2"))
	await(1)
	d, _ = tab.Lookup(addr("192.168.4.20"))
	if d.Name != "Sam's phone" {
		t.Errorf("name = %q, want the chosen one", d.Name)
	}

	// Clearing the name hands the device back to discovery rather than leaving
	// it permanently nameless.
	if err := tab.Rename(d.ID, ""); err != nil {
		t.Fatal(err)
	}
	await(1)
	tab.ObserveLease(lease("192.168.4.20", hw, "android-a94f2"))
	await(1)
	d, _ = tab.Lookup(addr("192.168.4.20"))
	if d.Name != "android-a94f2" {
		t.Errorf("name = %q after being cleared, want discovery to fill it in again", d.Name)
	}
}

// An address belongs to one device at a time. A stale mapping is how the next
// device to take an address inherits the previous one's rules.
func TestAnAddressMovingLeavesNothingBehind(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)
	shared := "192.168.4.20"

	tab.ObserveLease(lease(shared, net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, "tablet"))
	await(1)
	tablet, _ := tab.Lookup(addr(shared))
	if err := tab.SetProfile(tablet.ID, "kids"); err != nil {
		t.Fatal(err)
	}
	await(1)

	// The tablet leaves and a laptop takes the address.
	tab.ObserveLease(lease(shared, net.HardwareAddr{0x02, 0, 0, 0, 0, 2}, "laptop"))
	await(1)

	got, ok := tab.Lookup(addr(shared))
	if !ok {
		t.Fatal("the address identifies nobody")
	}
	if got.ID == tablet.ID {
		t.Fatal("the laptop was identified as the tablet")
	}
	if got.Profile == "kids" {
		t.Error("the laptop inherited the tablet's profile through a reused address")
	}
	old, ok := tab.Get(tablet.ID)
	if !ok {
		t.Fatal("the tablet was forgotten")
	}
	for _, a := range old.Addrs {
		if a == addr(shared) {
			t.Error("the tablet still lists an address another device now holds")
		}
	}
}

// An address on a local network is attacker-influenced, so the table is bounded
// — but a bound that silently dropped a device somebody had set a rule on would
// turn off that rule with no trace.
func TestEvictionNeverDropsAChosenDevice(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, func(o *Options) { o.MaxDevices = 4 })

	// Four devices, two of which a person has customised.
	for i := range 4 {
		tab.Identify(client(netip.AddrFrom4([4]byte{192, 168, 4, byte(10 + i)}).String()))
		await(1)
	}
	all := tab.Devices()
	if len(all) != 4 {
		t.Fatalf("%d devices, want 4", len(all))
	}
	if err := tab.Rename(all[0].ID, "named"); err != nil {
		t.Fatal(err)
	}
	await(1)
	if err := tab.SetPaused(all[1].ID, true); err != nil {
		t.Fatal(err)
	}
	await(1)

	// More arrive, forcing eviction.
	for i := range 3 {
		tab.Identify(client(netip.AddrFrom4([4]byte{192, 168, 4, byte(100 + i)}).String()))
		await(1)
	}
	if s := tab.Stats(); s.Devices > 4 {
		t.Errorf("the table grew past its bound: %+v", s)
	}
	if _, ok := tab.Get(all[0].ID); !ok {
		t.Error("the named device was evicted; the name a person chose was lost silently")
	}
	if _, ok := tab.Get(all[1].ID); !ok {
		t.Error("the paused device was evicted; a rule a person set was turned off silently")
	}
	if tab.Stats().Evicted == 0 {
		t.Error("evictions are not counted, so a full table is invisible")
	}
}

// If every device is customised the table refuses to grow rather than dropping
// somebody's decision: a full table is a visible problem, a forgotten rule is
// not.
func TestAFullTableOfChosenDevicesRefusesToGrow(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, func(o *Options) { o.MaxDevices = 2 })
	for i := range 2 {
		d, err := tab.Add("named", nil, netip.AddrFrom4([4]byte{192, 168, 4, byte(10 + i)}))
		if err != nil {
			t.Fatal(err)
		}
		await(1)
		if d.Name != "named" {
			t.Fatalf("device = %+v", d)
		}
	}
	if _, err := tab.Add("one too many", nil); !errors.Is(err, ErrFull) {
		t.Errorf("err = %v, want ErrFull", err)
	}
	if n := len(tab.Devices()); n != 2 {
		t.Errorf("%d devices, want the bound of 2", n)
	}
}

// No automatic identity scheme is reliable: a phone that rotates its hardware
// address arrives as a stranger, and only the person looking at the list knows
// the two are the same device.
func TestMergeFoldsTwoRecordsIntoOne(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)

	tab.ObserveLease(lease("192.168.4.20", net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, "phone"))
	await(1)
	first, _ := tab.Lookup(addr("192.168.4.20"))
	if err := tab.Rename(first.ID, "Sam's phone"); err != nil {
		t.Fatal(err)
	}
	await(1)

	// It comes back with a new randomised address.
	tab.ObserveLease(lease("192.168.4.21", net.HardwareAddr{0x02, 9, 9, 9, 9, 9}, "phone"))
	await(1)
	second, _ := tab.Lookup(addr("192.168.4.21"))
	if second.ID == first.ID {
		t.Fatal("the two records are already one; there is nothing to merge")
	}

	if err := tab.Merge(first.ID, second.ID); err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if n := len(tab.Devices()); n != 1 {
		t.Errorf("%d devices after a merge, want 1", n)
	}
	for _, a := range []string{"192.168.4.20", "192.168.4.21"} {
		d, ok := tab.Lookup(addr(a))
		if !ok || d.ID != first.ID {
			t.Errorf("%s resolves to %v %v, want the merged device", a, d.ID, ok)
		}
		if d.Name != "Sam's phone" {
			t.Errorf("%s: name = %q, want the target's", a, d.Name)
		}
	}
	// The old identity is gone, and merging something into itself is refused.
	if _, ok := tab.Get(second.ID); ok {
		t.Error("the merged-away device is still present")
	}
	if err := tab.Merge(first.ID, first.ID); err == nil {
		t.Error("a device was merged into itself")
	}
	if err := tab.Merge(first.ID, "dev-nope"); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("err = %v, want ErrUnknownDevice", err)
	}
}

// This is the deletion story for the most personal thing the product holds, so
// it has to be real.
func TestForgetGenuinelyForgets(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	tab.ObserveLease(lease("192.168.4.20", hw, "kids-tablet"))
	await(1)
	d, _ := tab.Lookup(addr("192.168.4.20"))

	if err := tab.Forget(d.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := tab.Get(d.ID); ok {
		t.Error("the device is still there")
	}
	if _, ok := tab.Lookup(addr("192.168.4.20")); ok {
		t.Error("the address still resolves to the forgotten device")
	}
	if got := tab.Identify(client("192.168.4.20")); got.ID != "" {
		t.Errorf("a query from the address is still identified as %q", got.ID)
	}
	// Nothing about it survives in a snapshot either.
	for k := range tab.Snapshot().Keys {
		if strings.Contains(k, string(hw)) {
			t.Error("the hardware address survives in the persisted state")
		}
	}
	if err := tab.Forget("dev-nope"); !errors.Is(err, ErrUnknownDevice) {
		t.Errorf("err = %v, want ErrUnknownDevice", err)
	}
}

// After a restart the leases are still held by the same devices. A table that
// waited to relearn every address would apply the default profile to every
// device on the network for the first queries after every restart — a filtering
// product briefly not filtering.
func TestStateRoundTripsIncludingAddresses(t *testing.T) {
	t.Parallel()
	tab, _, await := newTable(t, nil)
	hw := net.HardwareAddr{0x02, 0, 0, 0, 0, 1}
	tab.ObserveLease(lease("192.168.4.20", hw, "tablet"))
	await(1)
	d, _ := tab.Lookup(addr("192.168.4.20"))
	if err := tab.SetProfile(d.ID, "kids"); err != nil {
		t.Fatal(err)
	}
	await(1)
	if err := tab.SetPaused(d.ID, true); err != nil {
		t.Fatal(err)
	}
	await(1)
	snap := tab.Snapshot()

	restored, _, _ := newTable(t, nil)
	if err := restored.Restore(snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Identified on the very first query after the restart, with its profile.
	got := restored.Identify(client("192.168.4.20"))
	if got.ID != string(d.ID) {
		t.Fatalf("the first query after a restart identified %q, want %q", got.ID, d.ID)
	}
	again, ok := restored.Get(d.ID)
	if !ok {
		t.Fatal("the device did not survive the round trip")
	}
	if again.Profile != "kids" || !again.Paused || again.Name != "tablet" {
		t.Errorf("restored device = %+v", again)
	}
	// And the DHCP client key still points at it, so a renewal does not create
	// a second record.
	restored.ObserveLease(lease("192.168.4.30", hw, "tablet"))
	deadline := time.Now().Add(5 * time.Second)
	for len(restored.Devices()) == 1 && time.Now().Before(deadline) {
		if d2, ok := restored.Lookup(addr("192.168.4.30")); ok && d2.ID == d.ID {
			break
		}
	}
	if n := len(restored.Devices()); n != 1 {
		t.Errorf("%d devices after a renewal, want 1: the client key did not survive", n)
	}

	if err := restored.Restore(State{Version: 99}); err == nil {
		t.Error("an unsupported state version was accepted")
	}
}

// LastSeen must not cost a write per query, and must still be roughly right.
func TestLastSeenIsRefreshedButNotPerQuery(t *testing.T) {
	t.Parallel()
	tab, fake, await := newTable(t, func(o *Options) { o.SeenInterval = time.Minute })
	tab.ObserveLease(lease("192.168.4.20", net.HardwareAddr{0x02, 0, 0, 0, 0, 1}, "tablet"))
	await(1)
	before, _ := tab.Lookup(addr("192.168.4.20"))

	// A thousand queries inside the interval change nothing.
	for range 1000 {
		tab.Identify(client("192.168.4.20"))
	}
	if got, _ := tab.Lookup(addr("192.168.4.20")); !got.LastSeen.Equal(before.LastSeen) {
		t.Errorf("LastSeen moved to %v within the interval", got.LastSeen)
	}

	fake.Advance(2 * time.Minute)
	tab.Identify(client("192.168.4.20"))
	await(1)
	if got, _ := tab.Lookup(addr("192.168.4.20")); !got.LastSeen.After(before.LastSeen) {
		t.Errorf("LastSeen = %v, want it refreshed after the interval", got.LastSeen)
	}
}

// Identify runs on the query path while the DHCP server and a user interface
// are both mutating the table.
func TestIdentifyIsSafeWhileTheTableChanges(t *testing.T) {
	t.Parallel()
	tab, _, _ := newTable(t, nil)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tab.Identify(client("192.168.4.20"))
				tab.Lookup(addr("192.168.4.21"))
				_ = tab.Devices()
				_ = tab.Stats()
			}
		}()
	}
	for i := range 200 {
		hw := net.HardwareAddr{0x02, 0, 0, 0, byte(i >> 8), byte(i)}
		tab.ObserveLease(lease(netip.AddrFrom4([4]byte{192, 168, 4, byte(20 + i%200)}).String(), hw, "d"))
		if i%10 == 0 {
			for _, d := range tab.Devices() {
				_ = tab.Rename(d.ID, "renamed")
				break
			}
		}
	}
	close(stop)
	wg.Wait()
}

// Names arrive from a machine on the local network and from a person who may
// paste anything, and end up in a list, a log line and a JSON document.
func TestNamesAreSanitised(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ in, want string }{
		{"living room", "living room"},
		{"trailing\x00junk", "trailing"},
		{"line\r\nbreak", "linebreak"},
		{"  spaced  ", "spaced"},
		{strings.Repeat("a", 200), strings.Repeat("a", 64)},
	} {
		if got := SanitiseName(tc.in); got != tc.want {
			t.Errorf("SanitiseName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// A device the table has not caught up with must still resolve. Dropping the
// observation is the right trade; losing the query is not.
func TestAFullLearningQueueDropsObservationsNotQueries(t *testing.T) {
	t.Parallel()
	tab, _, _ := newTable(t, func(o *Options) { o.ObserveQueue = 1 })

	for i := range 5000 {
		got := tab.Identify(client(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()))
		if got.Addr.Addr().IsUnspecified() {
			t.Fatal("Identify mangled the client")
		}
	}
	if tab.Stats().Dropped == 0 {
		t.Error("nothing was dropped from a one-deep queue under five thousand new addresses")
	}
}

func TestUnknownDeviceOperationsAreRefused(t *testing.T) {
	t.Parallel()
	tab, _, _ := newTable(t, nil)
	for name, err := range map[string]error{
		"rename":  tab.Rename("dev-nope", "x"),
		"profile": tab.SetProfile("dev-nope", "kids"),
		"pause":   tab.SetPaused("dev-nope", true),
		"forget":  tab.Forget("dev-nope"),
	} {
		if !errors.Is(err, ErrUnknownDevice) {
			t.Errorf("%s: err = %v, want ErrUnknownDevice", name, err)
		}
	}
}

// An identifier must carry no information about how many devices there are or
// in what order they appeared, and two tables merged by hand must not collide.
func TestIdentifiersAreOpaqueAndUnique(t *testing.T) {
	t.Parallel()
	seen := map[ID]bool{}
	for range 1000 {
		id := newID()
		if seen[id] {
			t.Fatalf("duplicate identifier %s", id)
		}
		if !strings.HasPrefix(string(id), "dev-") || len(id) < 12 {
			t.Fatalf("identifier %q does not look opaque", id)
		}
		seen[id] = true
	}
}
