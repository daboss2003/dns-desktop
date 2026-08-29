package dhcp

import (
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gatewaydns/gatewaydns/clock"
)

var epoch = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// testPool is a /24 with a ten-address range, small enough that exhaustion is
// reachable in a test and wide enough that allocation order is visible.
func testPool(t testing.TB, mutate func(*PoolOptions)) (*Pool, *clock.Fake) {
	t.Helper()
	fake := clock.NewFake(epoch)
	opts := PoolOptions{
		Subnet: netip.MustParsePrefix("192.168.4.0/24"),
		First:  addr("192.168.4.10"),
		Last:   addr("192.168.4.19"),
		// Inside the range, standing for a device somebody gave a static
		// address by hand. An exclusion outside the range would test nothing.
		Excluded: []netip.Addr{addr("192.168.4.11")},
		Clock:    fake,
	}
	if mutate != nil {
		mutate(&opts)
	}
	p, err := NewPool(opts)
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	return p, fake
}

func hw(last byte) net.HardwareAddr { return net.HardwareAddr{0x02, 0, 0, 0, 0, last} }

// lease takes a client all the way through DISCOVER/OFFER/REQUEST/ACK.
func lease(t testing.TB, p *Pool, key string, n byte, host string) Lease {
	t.Helper()
	offered, err := p.Offer(key, netip.Addr{}, hw(n), host)
	if err != nil {
		t.Fatalf("Offer(%s): %v", key, err)
	}
	got, err := p.Commit(key, offered.Addr, hw(n), host)
	if err != nil {
		t.Fatalf("Commit(%s, %v): %v", key, offered.Addr, err)
	}
	return got
}

// TestAReconnectingDeviceKeepsItsAddress is the property the whole product
// rests on. Per-device policy is applied by source address on the DNS path, so
// a device whose address changes on every reconnect is a device whose rules
// keep coming off — and the person who set them sees filtering that works
// until it randomly does not.
func TestAReconnectingDeviceKeepsItsAddress(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, nil)

	first := lease(t, p, "hw:phone", 1, "phone")
	// Other devices come and go in between, so the address is not simply the
	// first one free.
	for i := byte(2); i < 6; i++ {
		lease(t, p, string(rune('a'+i)), i, "")
	}
	p.Release("hw:phone", first.Addr)

	// A week later, with the lease long expired.
	fake.Advance(7 * 24 * time.Hour)
	again := lease(t, p, "hw:phone", 1, "phone")
	if again.Addr != first.Addr {
		t.Errorf("the device came back as %v, having been %v", again.Addr, first.Addr)
	}
	if again.FirstSeen != first.FirstSeen {
		t.Errorf("FirstSeen moved from %v to %v; the device's history was forgotten",
			first.FirstSeen, again.FirstSeen)
	}
}

// Two clients that DISCOVER before either REQUESTs must not be offered the same
// address, or both request it and one is NAKed for no reason it can see.
func TestSimultaneousDiscoversGetDifferentAddresses(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)

	a, err := p.Offer("hw:a", netip.Addr{}, hw(1), "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Offer("hw:b", netip.Addr{}, hw(2), "b")
	if err != nil {
		t.Fatal(err)
	}
	if a.Addr == b.Addr {
		t.Fatalf("both clients were offered %v", a.Addr)
	}
	// And both offers can be committed.
	if _, err := p.Commit("hw:a", a.Addr, hw(1), "a"); err != nil {
		t.Errorf("committing the first offer: %v", err)
	}
	if _, err := p.Commit("hw:b", b.Addr, hw(2), "b"); err != nil {
		t.Errorf("committing the second offer: %v", err)
	}
}

// A client that vanishes between OFFER and REQUEST must not hold an address for
// the whole lease period. On a guest network that is how a ten-address range
// runs out with two devices connected.
func TestAnAbandonedOfferIsReclaimedQuickly(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, func(o *PoolOptions) {
		o.Lease = 12 * time.Hour
		o.OfferHold = 30 * time.Second
	})

	offered, err := p.Offer("hw:ghost", netip.Addr{}, hw(1), "ghost")
	if err != nil {
		t.Fatal(err)
	}
	if s := p.Stats(); s.Offered != 1 {
		t.Fatalf("stats = %+v, want one offered", s)
	}

	fake.Advance(29 * time.Second)
	if s := p.Stats(); s.Offered != 1 {
		t.Errorf("the offer lapsed early: %+v", s)
	}
	fake.Advance(2 * time.Second)
	if s := p.Stats(); s.Offered != 0 || s.Free != s.Total {
		t.Errorf("stats = %+v, want the offer reclaimed after the hold", s)
	}

	// The address is allocatable again, and the ghost's history is not lost.
	other, err := p.Offer("hw:other", offered.Addr, hw(2), "other")
	if err != nil {
		t.Fatal(err)
	}
	if other.Addr != offered.Addr {
		t.Errorf("the reclaimed address was not reused: got %v, want %v", other.Addr, offered.Addr)
	}
}

// A reservation is the operator's explicit instruction and beats everything.
func TestReservationsAlwaysWin(t *testing.T) {
	t.Parallel()
	pinned := addr("192.168.4.12")
	p, fake := testPool(t, func(o *PoolOptions) {
		o.Reserved = []Reservation{ReservationForHardware(hw(9), pinned, "printer")}
	})

	// Fill everything else first, so the reserved address is the only one left
	// that a dynamic client could stumble onto.
	for i := byte(1); i < 9; i++ {
		if _, err := p.Offer(string(rune('a'+i)), pinned, hw(i), ""); err != nil {
			t.Fatalf("filling the pool: %v", err)
		}
		if got, _ := p.Lookup(string(rune('a' + i))); got.Addr == pinned {
			t.Fatalf("client %d was given the reserved address %v", i, pinned)
		}
	}

	got := lease(t, p, "hw:"+string(hw(9)), 9, "")
	if got.Addr != pinned {
		t.Errorf("the reserved client got %v, want %v", got.Addr, pinned)
	}
	if got.Hostname != "printer" {
		t.Errorf("hostname = %q, want the reserved name", got.Hostname)
	}
	// A reservation does not expire.
	fake.Advance(365 * 24 * time.Hour)
	if l, ok := p.Lookup("hw:" + string(hw(9))); !ok || l.Addr != pinned || l.State != Reserved {
		t.Errorf("the reservation lapsed: %+v %v", l, ok)
	}
}

// A DHCPRELEASE is unauthenticated. Honouring one for somebody else's address
// is a one-packet denial of service against any device on the network.
func TestReleaseOfAnotherClientsAddressIsIgnored(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)
	victim := lease(t, p, "hw:victim", 1, "victim")

	p.Release("hw:attacker", victim.Addr)

	got, ok := p.LookupAddr(victim.Addr)
	if !ok || got.Key != "hw:victim" {
		t.Errorf("the lease was released by a client that did not hold it: %+v %v", got, ok)
	}
}

// RFC 2131 section 4.3.3: a declined address is held by something we do not
// know about. Returning it to the pool produces the same collision for the next
// client, and the next, indefinitely.
func TestDeclinedAddressesAreQuarantined(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, nil)
	l := lease(t, p, "hw:a", 1, "a")

	p.Decline("hw:a", l.Addr)
	if s := p.Stats(); s.Declined != 1 {
		t.Fatalf("stats = %+v, want one declined", s)
	}

	// Nobody is given it, even after everything else has been handed out and
	// long after any lease would have lapsed.
	fake.Advance(30 * 24 * time.Hour)
	for i := byte(2); i < 12; i++ {
		got, err := p.Offer(string(rune('a'+i)), l.Addr, hw(i), "")
		if errors.Is(err, ErrPoolExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if got.Addr == l.Addr {
			t.Fatalf("the declined address %v was handed to another client", l.Addr)
		}
	}
	// An administrator can return it deliberately.
	if !p.Free(l.Addr) {
		t.Error("Free did not release the declined address")
	}
	if s := p.Stats(); s.Declined != 0 {
		t.Errorf("stats = %+v, want it freed", s)
	}
}

func TestExhaustionIsReportedAsItself(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)
	var n int
	for i := 0; i < 100; i++ {
		_, err := p.Offer(strings.Repeat("k", i+1), netip.Addr{}, hw(byte(i)), "")
		if errors.Is(err, ErrPoolExhausted) {
			break
		}
		if err != nil {
			t.Fatalf("Offer: %v", err)
		}
		n++
	}
	// Ten addresses in the range, less the one excluded.
	if n != 9 {
		t.Errorf("allocated %d addresses, want 9", n)
	}
	if _, err := p.Offer("one-more", netip.Addr{}, hw(99), ""); !errors.Is(err, ErrPoolExhausted) {
		t.Errorf("err = %v, want ErrPoolExhausted — it is the one failure an operator can act on", err)
	}
}

// A client handed the network or broadcast address is broken in a way that
// presents as a hardware fault: it associates, it gets an address, nothing
// routes.
func TestNetworkAndBroadcastAddressesAreNeverAllocated(t *testing.T) {
	t.Parallel()
	p, err := NewPool(PoolOptions{
		Subnet: netip.MustParsePrefix("192.168.4.0/29"),
		First:  addr("192.168.4.0"),
		Last:   addr("192.168.4.7"),
		Clock:  clock.NewFake(epoch),
	})
	if err != nil {
		t.Fatal(err)
	}
	forbidden := map[netip.Addr]bool{addr("192.168.4.0"): true, addr("192.168.4.7"): true}
	for i := 0; i < 10; i++ {
		got, err := p.Offer(strings.Repeat("k", i+1), netip.Addr{}, hw(byte(i)), "")
		if errors.Is(err, ErrPoolExhausted) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if forbidden[got.Addr] {
			t.Fatalf("allocated %v, which is the network or broadcast address of %v", got.Addr, p.Subnet())
		}
	}
	if s := p.Stats(); s.Total != 6 {
		t.Errorf("the pool holds %d addresses, want 6 for a /29 less network and broadcast", s.Total)
	}
}

// RFC 2131 section 4.3.1 prefers the address unassigned longest. Picking the
// lowest free address instead hands a returning device somebody else's old
// address and gives its own away, so a household's addresses shuffle every time
// anyone leaves.
func TestAllocationPrefersTheLongestFreeAddress(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, nil)

	// Take every address, so that what is left to allocate is only what has
	// been recycled — otherwise a never-used address wins, which is the
	// property the next test pins.
	keys := make([]string, 0, 9)
	held := make([]Lease, 0, 9)
	for i := range 9 {
		key := strings.Repeat("k", i+1)
		keys = append(keys, key)
		held = append(held, lease(t, p, key, byte(i), ""))
		fake.Advance(time.Second)
	}

	// Two leave, in a known order and a known interval apart.
	p.Release(keys[4], held[4].Addr)
	fake.Advance(time.Minute)
	p.Release(keys[2], held[2].Addr)
	fake.Advance(time.Minute)

	got, err := p.Offer("newcomer", netip.Addr{}, hw(99), "newcomer")
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != held[4].Addr {
		t.Errorf("the newcomer got %v; %v had been free a minute longer", got.Addr, held[4].Addr)
	}
}

// An address that has never been assigned belongs to nobody, so spending it
// costs no device its old address — while recycling one freed an hour ago may.
func TestNeverUsedAddressesAreSpentFirst(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, nil)
	first := lease(t, p, "hw:phone", 1, "phone")
	p.Release("hw:phone", first.Addr)
	fake.Advance(time.Hour)

	for i := range 4 {
		got, err := p.Offer(strings.Repeat("n", i+1), netip.Addr{}, hw(byte(20+i)), "")
		if err != nil {
			t.Fatal(err)
		}
		if got.Addr == first.Addr {
			t.Fatalf("newcomer %d was given %v, which the phone had; untouched addresses were still free", i, got.Addr)
		}
	}
	// And the phone still gets it back.
	again := lease(t, p, "hw:phone", 1, "phone")
	if again.Addr != first.Addr {
		t.Errorf("the phone came back as %v, having been %v", again.Addr, first.Addr)
	}
}

// A freed address must not identify the device that used to hold it. The next
// device to take it would arrive wearing the previous one's identity, and with
// it the previous one's rules — so the tablet a household filters would be
// treated as the laptop it does not, and nothing in the UI would look wrong.
func TestAFreedAddressIdentifiesNobody(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, func(o *PoolOptions) { o.Lease = time.Hour })

	kid := lease(t, p, "hw:tablet", 1, "kids-tablet")
	if got, ok := p.LookupAddr(kid.Addr); !ok || got.Key != "hw:tablet" {
		t.Fatalf("LookupAddr = %+v %v, want the tablet", got, ok)
	}

	// Released.
	p.Release("hw:tablet", kid.Addr)
	if got, ok := p.LookupAddr(kid.Addr); ok {
		t.Errorf("a released address still identifies %q", got.Key)
	}

	// Expired, which is the case that happens without anyone doing anything.
	again := lease(t, p, "hw:tablet", 1, "kids-tablet")
	fake.Advance(2 * time.Hour)
	if got, ok := p.LookupAddr(again.Addr); ok {
		t.Errorf("an expired address still identifies %q", got.Key)
	}

	// An offer is not a binding either: the client is still completing its
	// handshake from 0.0.0.0 and is not using the address yet.
	offered, err := p.Offer("hw:new", netip.Addr{}, hw(2), "new")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.LookupAddr(offered.Addr); ok {
		t.Error("an offered address identifies a device that has not accepted it")
	}

	// The device list still remembers all of them, which is where that memory
	// belongs.
	var names int
	for _, l := range p.Leases() {
		if l.Hostname != "" {
			names++
		}
	}
	if names == 0 {
		t.Error("the device list forgot every device")
	}
}

// A client that asks for an address another client holds must be refused, not
// quietly moved: two devices confidently using one address is worse than one
// device being told to start again.
func TestCommitRefusesAnotherClientsAddress(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)
	held := lease(t, p, "hw:holder", 1, "holder")

	_, err := p.Commit("hw:thief", held.Addr, hw(2), "thief")
	if !errors.Is(err, ErrTaken) {
		t.Errorf("err = %v, want ErrTaken", err)
	}
	if got, _ := p.LookupAddr(held.Addr); got.Key != "hw:holder" {
		t.Errorf("the binding moved to %q", got.Key)
	}

	// An address outside the pool is a different failure: the client has moved
	// networks and must be NAKed so it restarts.
	_, err = p.Commit("hw:roamer", addr("10.0.0.5"), hw(3), "roamer")
	if !errors.Is(err, ErrNotOurs) {
		t.Errorf("err = %v, want ErrNotOurs", err)
	}
}

// One laptop must not accumulate three addresses over an afternoon of network
// changes.
func TestMovingAddressReleasesTheOldOne(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)
	first := lease(t, p, "hw:laptop", 1, "laptop")

	// It comes back asking for a different address, as a client does after
	// being on another network.
	other := addr("192.168.4.18")
	if _, err := p.Commit("hw:laptop", other, hw(1), "laptop"); err != nil {
		t.Fatal(err)
	}
	if _, ok := p.LookupAddr(first.Addr); ok {
		t.Errorf("%v is still bound after the client moved to %v", first.Addr, other)
	}
	if got, ok := p.Lookup("hw:laptop"); !ok || got.Addr != other {
		t.Errorf("Lookup = %+v, want %v", got, other)
	}
	var held int
	for _, l := range p.Leases() {
		if l.Key == "hw:laptop" && l.State == Leased {
			held++
		}
	}
	if held != 1 {
		t.Errorf("the client holds %d addresses, want 1", held)
	}
}

// A device list that emptied every morning would be useless, so an expired
// binding keeps its identity and history and only loses its claim.
func TestExpiredLeasesStayInTheDeviceList(t *testing.T) {
	t.Parallel()
	p, fake := testPool(t, func(o *PoolOptions) { o.Lease = time.Hour })
	l := lease(t, p, "hw:phone", 1, "phone")

	fake.Advance(2 * time.Hour)
	if _, ok := p.LookupAddr(l.Addr); ok {
		t.Error("an expired lease still answers an address lookup")
	}
	found := false
	for _, got := range p.Leases() {
		if got.Key == "hw:phone" {
			found = true
			if got.Hostname != "phone" {
				t.Errorf("the name was forgotten: %+v", got)
			}
			if got.State != Free {
				t.Errorf("state = %v, want free", got.State)
			}
		}
	}
	if !found {
		t.Error("the device vanished from the list when its lease lapsed")
	}
	if s := p.Stats(); s.Leased != 0 || s.Free != s.Total {
		t.Errorf("stats = %+v, want everything free", s)
	}
}

// Several clients renew without repeating option 12. Blanking the name would
// empty the device list the first time that happened.
func TestARenewalWithoutAHostnameKeepsTheName(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)
	l := lease(t, p, "hw:phone", 1, "living-room")

	again, err := p.Commit("hw:phone", l.Addr, hw(1), "")
	if err != nil {
		t.Fatal(err)
	}
	if again.Hostname != "living-room" {
		t.Errorf("hostname = %q after a renewal that omitted option 12, want it kept", again.Hostname)
	}
}

func TestBadPoolsAreRefusedAtConstruction(t *testing.T) {
	t.Parallel()
	base := func() PoolOptions {
		return PoolOptions{
			Subnet: netip.MustParsePrefix("192.168.4.0/24"),
			First:  addr("192.168.4.10"),
			Last:   addr("192.168.4.19"),
		}
	}
	for _, tc := range []struct {
		name  string
		build func(*PoolOptions)
		want  string
	}{
		{"reversed range", func(o *PoolOptions) { o.First, o.Last = o.Last, o.First }, "above"},
		{"outside the subnet", func(o *PoolOptions) { o.Last = addr("192.168.5.10") }, "outside"},
		{"absurdly large", func(o *PoolOptions) {
			o.Subnet = netip.MustParsePrefix("10.0.0.0/8")
			o.First, o.Last = addr("10.0.0.1"), addr("10.255.255.254")
		}, "typo"},
		{"no range", func(o *PoolOptions) { o.First, o.Last = netip.Addr{}, netip.Addr{} }, "first and a last"},
		{"empty after exclusions", func(o *PoolOptions) {
			o.Last = o.First
			o.Excluded = []netip.Addr{o.First}
		}, "empty"},
		{"reservation outside the subnet", func(o *PoolOptions) {
			o.Reserved = []Reservation{{Key: "hw:x", Addr: addr("10.1.1.1")}}
		}, "outside subnet"},
		{"two reservations for one address", func(o *PoolOptions) {
			o.Reserved = []Reservation{
				{Key: "hw:a", Addr: addr("192.168.4.12")},
				{Key: "hw:b", Addr: addr("192.168.4.12")},
			}
		}, "reserved twice"},
		{"two addresses for one client", func(o *PoolOptions) {
			o.Reserved = []Reservation{
				{Key: "hw:a", Addr: addr("192.168.4.12")},
				{Key: "hw:a", Addr: addr("192.168.4.13")},
			}
		}, "two addresses"},
		{"reservation with no key", func(o *PoolOptions) {
			o.Reserved = []Reservation{{Addr: addr("192.168.4.12")}}
		}, "no client key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			opts := base()
			tc.build(&opts)
			_, err := NewPool(opts)
			if err == nil {
				t.Fatalf("%+v was accepted", opts)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

// A reservation outside the dynamic range is legitimate and is the usual
// advice: reserve below the pool so the two cannot collide.
func TestReservationsMayLieOutsideTheDynamicRange(t *testing.T) {
	t.Parallel()
	pinned := addr("192.168.4.5")
	p, _ := testPool(t, func(o *PoolOptions) {
		o.Reserved = []Reservation{ReservationForHardware(hw(9), pinned, "nas")}
	})
	got, err := p.Offer("hw:"+string(hw(9)), netip.Addr{}, hw(9), "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Addr != pinned {
		t.Errorf("got %v, want the reserved %v", got.Addr, pinned)
	}
}

// The pool decides who is allowed on the network, and it is reached from the
// DHCP socket and from the UI at the same time.
func TestPoolIsSafeUnderConcurrentUse(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, func(o *PoolOptions) {
		o.First, o.Last = addr("192.168.4.10"), addr("192.168.4.200")
	})

	var wg sync.WaitGroup
	for i := range 40 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := strings.Repeat("k", i+1)
			for range 20 {
				l, err := p.Offer(key, netip.Addr{}, hw(byte(i)), "d")
				if err != nil {
					continue
				}
				_, _ = p.Commit(key, l.Addr, hw(byte(i)), "d")
				_, _ = p.Lookup(key)
				_, _ = p.LookupAddr(l.Addr)
				_ = p.Stats()
				_ = p.Leases()
			}
		}()
	}
	wg.Wait()

	// However the races fell out, no address may be bound to two clients.
	seen := map[netip.Addr]string{}
	for _, l := range p.Leases() {
		if prev, ok := seen[l.Addr]; ok {
			t.Errorf("%v is bound to both %q and %q", l.Addr, prev, l.Key)
		}
		seen[l.Addr] = l.Key
	}
}
