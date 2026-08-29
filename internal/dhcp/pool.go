package dhcp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/gatewaydns/gatewaydns/clock"
)

// State is where an address in the pool stands.
type State uint8

const (
	// Free is available for allocation.
	Free State = iota
	// Offered is held for one client that has been sent a DHCPOFFER but has
	// not yet requested it. Without this state two clients that DISCOVER at the
	// same moment are offered the same address, both REQUEST it, and one of
	// them is NAKed for no reason it can see.
	Offered
	// Leased is bound to a client.
	Leased
	// Declined is an address a client told us was already in use (RFC 2131
	// section 4.3.3). Something on this network holds it that we do not know
	// about, and handing it to somebody else produces the same collision again.
	Declined
	// Reserved is statically assigned to one client and is never given to
	// another, whether or not that client is present.
	Reserved
)

func (s State) String() string {
	switch s {
	case Free:
		return "free"
	case Offered:
		return "offered"
	case Leased:
		return "leased"
	case Declined:
		return "declined"
	case Reserved:
		return "reserved"
	default:
		return "unknown"
	}
}

// Lease is one address binding.
//
// It is a value: [Pool] hands out copies, so a caller can hold one, log it and
// put it in a JSON document without the pool's own state changing underneath.
type Lease struct {
	// Key is the client identity from [Message.ClientKey] — the client
	// identifier when the client sends one, the hardware address otherwise
	// (RFC 2131 section 4.3.1).
	Key string `json:"key"`
	// Addr is the assigned address.
	Addr netip.Addr `json:"addr"`
	// HWAddr is the hardware address last seen using this binding. It is not
	// the identity — Key is — but it is what a person recognises in a device
	// list, and it is how a manufacturer is looked up.
	HWAddr net.HardwareAddr `json:"hwaddr,omitempty"`
	// Hostname is what the client called itself, already sanitised.
	Hostname string `json:"hostname,omitempty"`
	// State is where this address stands.
	State State `json:"-"`
	// Expires is when the lease ends. Zero means it does not: a reservation, or
	// the infinite lease of RFC 2131 section 3.3.
	Expires time.Time `json:"expires,omitzero"`
	// FirstSeen and LastSeen bracket the client's history with us, and are what
	// a device list sorts and filters on.
	FirstSeen time.Time `json:"first_seen,omitzero"`
	LastSeen  time.Time `json:"last_seen,omitzero"`
}

// Expired reports whether the lease has ended as of now.
func (l Lease) Expired(now time.Time) bool {
	return !l.Expires.IsZero() && !now.Before(l.Expires)
}

// Reservation statically assigns one address to one client.
//
// The key is matched against [Message.ClientKey], so a reservation written
// against a hardware address does not apply to a client that sends a client
// identifier. [ReservationForHardware] builds the key correctly.
type Reservation struct {
	Key      string     `json:"key"`
	Addr     netip.Addr `json:"addr"`
	Hostname string     `json:"hostname,omitempty"`
}

// ReservationForHardware builds a reservation keyed on a hardware address.
//
// It exists because the key format is an implementation detail that a
// configuration file must not have to know, and because getting it wrong
// produces a reservation that silently never matches — the worst possible
// failure for a setting whose whole purpose is that one device always has one
// address.
func ReservationForHardware(hw net.HardwareAddr, addr netip.Addr, hostname string) Reservation {
	return Reservation{Key: "hw:" + string(hw), Addr: addr, Hostname: hostname}
}

// Errors from [Pool].
var (
	// ErrPoolExhausted reports that every address is spoken for. It is
	// distinct because it is the one allocation failure an operator can act on,
	// by widening the range.
	ErrPoolExhausted = errors.New("dhcp: no addresses are available in the pool")
	// ErrNotOurs reports an address outside the pool's range. A client asking
	// for one has moved between networks and must be NAKed (RFC 2131 section
	// 4.3.2) so that it restarts rather than using an address that will not
	// route.
	ErrNotOurs = errors.New("dhcp: address is not in this pool")
	// ErrTaken reports an address held by a different client.
	ErrTaken = errors.New("dhcp: address is held by another client")
)

// MaxPoolSize bounds how many addresses a pool may cover.
//
// A DHCP pool is materialised in memory so that allocation is a map lookup
// rather than a scan of a sparse structure, and 65536 entries is about 12 MiB —
// affordable on the router-sized hardware this runs on. It is a bound rather
// than a growth strategy because a range this large on a household network is a
// typo, and diagnosing a typo at start-up is better than discovering it as
// memory pressure a week later.
const MaxPoolSize = 1 << 16

// PoolOptions configure a [Pool].
type PoolOptions struct {
	// Subnet is the network the pool serves. Addresses outside it are refused
	// with [ErrNotOurs].
	Subnet netip.Prefix
	// First and Last bound the allocatable range, inclusive. Both must lie
	// inside Subnet.
	First, Last netip.Addr
	// Lease is how long a lease lasts. Zero selects [DefaultLease].
	Lease time.Duration
	// OfferHold is how long an address is reserved for a client that has been
	// offered it. Zero selects [DefaultOfferHold]. It is short by design: a
	// client that vanishes between OFFER and REQUEST must not hold an address
	// for the whole lease period, which on a busy guest network is how a /24
	// runs out with four devices connected.
	OfferHold time.Duration
	// Reserved are static assignments, applied before any dynamic allocation.
	Reserved []Reservation
	// Excluded are addresses inside the range that must never be allocated:
	// the router, this server, anything with a static address configured by
	// hand. The network and broadcast addresses of Subnet are excluded
	// automatically, because assigning either breaks the client that receives
	// it in a way that looks like a hardware fault.
	Excluded []netip.Addr

	Clock clock.Clock
}

// Defaults for [PoolOptions].
const (
	// DefaultLease is twelve hours: long enough that a laptop keeps its address
	// across a working day, short enough that a guest's address returns to the
	// pool the same day they leave.
	DefaultLease = 12 * time.Hour
	// DefaultOfferHold is thirty seconds, comfortably longer than the four
	// retransmissions RFC 2131 section 4.1 has a client make before giving up,
	// and short enough that an abandoned offer costs one address for half a
	// minute.
	DefaultOfferHold = 30 * time.Second
)

// Pool allocates addresses and remembers who has them.
//
// It is safe for concurrent use, and every method takes the whole lock: DHCP
// runs at a handful of messages per device per lease period, so there is
// nothing here worth the complexity of finer locking, and a single lock is one
// fewer thing to reason about in code that decides who gets to be on the
// network.
//
// Expiry is lazy. A lease is checked against the clock when it is looked at
// rather than swept by a timer, so a pool with no traffic costs nothing and a
// clock that jumps cannot expire everything at once — [clock.System] carries
// Go's monotonic reading for exactly that reason.
type Pool struct {
	mu       sync.Mutex
	clk      clock.Clock
	subnet   netip.Prefix
	lease    time.Duration
	offerTTL time.Duration

	// addrs is the allocatable range in ascending order, and entries is the
	// state of each. They are parallel so that allocation can scan in address
	// order — a device list sorted by address is what a person expects, and an
	// allocator that hands out 192.168.4.137 first makes that list nonsense.
	addrs   []netip.Addr
	entries map[netip.Addr]*entry
	byKey   map[string]*entry
}

type entry struct {
	addr      netip.Addr
	state     State
	key       string
	hw        net.HardwareAddr
	hostname  string
	expires   time.Time
	firstSeen time.Time
	lastSeen  time.Time
	// freedAt is when this address last became free, and orders reuse:
	// RFC 2131 section 4.3.1 has a server prefer the address that has been
	// unassigned longest, which gives a departing device the best chance of
	// getting its old address back.
	freedAt time.Time
}

func (e *entry) lease() Lease {
	return Lease{
		Key: e.key, Addr: e.addr, HWAddr: e.hw, Hostname: e.hostname,
		State: e.state, Expires: e.expires,
		FirstSeen: e.firstSeen, LastSeen: e.lastSeen,
	}
}

// NewPool builds a pool.
func NewPool(opts PoolOptions) (*Pool, error) {
	if !opts.Subnet.IsValid() || !opts.Subnet.Addr().Is4() {
		return nil, fmt.Errorf("dhcp: subnet %v is not a valid IPv4 prefix", opts.Subnet)
	}
	subnet := opts.Subnet.Masked()
	first, last := opts.First, opts.Last
	if !first.IsValid() || !last.IsValid() {
		return nil, errors.New("dhcp: the pool needs a first and a last address")
	}
	if !first.Is4() || !last.Is4() {
		return nil, fmt.Errorf("dhcp: range %v-%v is not IPv4", first, last)
	}
	if first.Compare(last) > 0 {
		return nil, fmt.Errorf("dhcp: first address %v is above last address %v", first, last)
	}
	for _, a := range []netip.Addr{first, last} {
		if !subnet.Contains(a) {
			return nil, fmt.Errorf("dhcp: address %v is outside subnet %v", a, subnet)
		}
	}
	size := addrDistance(first, last) + 1
	if size > MaxPoolSize {
		return nil, fmt.Errorf(
			"dhcp: range %v-%v covers %d addresses, more than the %d this server will hold; "+
				"a range that size on one link is usually a typo in the last octet",
			first, last, size, MaxPoolSize)
	}

	p := &Pool{
		clk:      clock.OrSystem(opts.Clock),
		subnet:   subnet,
		lease:    orDuration(opts.Lease, DefaultLease),
		offerTTL: orDuration(opts.OfferHold, DefaultOfferHold),
		addrs:    make([]netip.Addr, 0, size),
		entries:  make(map[netip.Addr]*entry, size),
		byKey:    make(map[string]*entry),
	}

	// The network and broadcast addresses are excluded whatever the range says.
	// A client handed either is broken in a way that presents as a hardware
	// fault — it associates, it gets an address, and nothing routes.
	skip := map[netip.Addr]bool{
		subnet.Addr():       true,
		broadcastOf(subnet): true,
	}
	for _, a := range opts.Excluded {
		skip[a] = true
	}

	for a := first; ; a = a.Next() {
		if !skip[a] {
			e := &entry{addr: a}
			p.addrs = append(p.addrs, a)
			p.entries[a] = e
		}
		if a == last {
			break
		}
	}
	if len(p.addrs) == 0 {
		return nil, fmt.Errorf("dhcp: range %v-%v is empty once exclusions are applied", first, last)
	}

	for _, r := range opts.Reserved {
		if err := p.reserve(r); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// reserve installs a static assignment. The caller holds no lock: this runs
// only from NewPool, before the pool is shared.
func (p *Pool) reserve(r Reservation) error {
	if r.Key == "" {
		return fmt.Errorf("dhcp: reservation for %v has no client key", r.Addr)
	}
	e, ok := p.entries[r.Addr]
	if !ok {
		// A reservation outside the dynamic range is legitimate and common —
		// the usual advice is to reserve below the pool so the two cannot
		// collide — but it must still be inside the subnet, or the client
		// cannot route.
		if !p.subnet.Contains(r.Addr) {
			return fmt.Errorf("dhcp: reservation %v for %q is outside subnet %v", r.Addr, r.Key, p.subnet)
		}
		e = &entry{addr: r.Addr}
		p.entries[r.Addr] = e
	}
	if e.state == Reserved && e.key != r.Key {
		return fmt.Errorf("dhcp: %v is reserved twice, for %q and %q", r.Addr, e.key, r.Key)
	}
	if prev, ok := p.byKey[r.Key]; ok && prev.addr != r.Addr {
		return fmt.Errorf("dhcp: client %q is reserved two addresses, %v and %v", r.Key, prev.addr, r.Addr)
	}
	e.state, e.key, e.hostname = Reserved, r.Key, r.Hostname
	p.byKey[r.Key] = e
	return nil
}

// Offer chooses an address for a client and holds it briefly.
//
// The order is RFC 2131 section 4.3.1's, and each step exists for a reason a
// user would notice:
//
//  1. A reservation, which is the operator's explicit instruction.
//  2. The client's current binding, so a device that reconnects keeps its
//     address. This one is load-bearing for the whole product: per-device
//     policy is applied by source address on the DNS path, and a device whose
//     address changes on every reconnect is a device whose rules keep coming
//     off.
//  3. The address the client asked for, if it is free.
//  4. The client's most recent expired binding, if nobody took it.
//  5. The address that has been free the longest, which is what gives a device
//     returning after a week the best chance of its old address.
func (p *Pool) Offer(key string, req netip.Addr, hw net.HardwareAddr, hostname string) (Lease, error) {
	if key == "" {
		return Lease{}, errors.New("dhcp: cannot offer an address to a client with no identity")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clk.Now()
	p.expireLocked(now)

	if e, ok := p.byKey[key]; ok {
		p.bindLocked(e, key, hw, hostname, now, e.state == Reserved)
		return e.lease(), nil
	}
	if e, ok := p.entries[req]; ok && p.availableLocked(e, key) {
		p.bindLocked(e, key, hw, hostname, now, false)
		return e.lease(), nil
	}
	if e := p.leastRecentlyFreedLocked(); e != nil {
		p.bindLocked(e, key, hw, hostname, now, false)
		return e.lease(), nil
	}
	return Lease{}, ErrPoolExhausted
}

// Commit turns an offer into a lease, or renews one.
//
// It refuses rather than reassigning when the address belongs to somebody else:
// a client that asks for an address another client holds must be NAKed, and a
// server that quietly moved the binding would produce two devices confidently
// using one address.
func (p *Pool) Commit(key string, addr netip.Addr, hw net.HardwareAddr, hostname string) (Lease, error) {
	if key == "" {
		return Lease{}, errors.New("dhcp: cannot commit a lease for a client with no identity")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.clk.Now()
	p.expireLocked(now)

	e, ok := p.entries[addr]
	if !ok {
		return Lease{}, fmt.Errorf("%w: %v is not in %v", ErrNotOurs, addr, p.subnet)
	}
	if !p.availableLocked(e, key) {
		return Lease{}, fmt.Errorf("%w: %v is %s by %q", ErrTaken, addr, e.state, e.key)
	}
	// Read before binding, because bindLocked rewrites it. A reservation that
	// were downgraded here would become a twelve-hour lease and then expire,
	// which is the one thing a reservation exists not to do.
	reserved := e.state == Reserved

	// A client that moves to an address it was not offered leaves its old
	// binding behind. Releasing it here is what stops one laptop accumulating
	// three addresses over an afternoon of network changes.
	if prev, ok := p.byKey[key]; ok && prev != e && prev.state != Reserved {
		p.freeLocked(prev, now)
	}
	p.bindLocked(e, key, hw, hostname, now, reserved)
	if !reserved {
		e.state = Leased
		e.expires = now.Add(p.lease)
	}
	return e.lease(), nil
}

// Release returns a lease to the pool at the client's request (DHCPRELEASE).
//
// The binding's identity, hostname and history are kept and the address is
// marked free. Forgetting the client would mean the device reappears as a
// stranger with no name in the device list, which is exactly the moment a
// person is looking at that list.
func (p *Pool) Release(key string, addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[addr]
	if !ok || e.key != key || e.state == Reserved {
		// Not a client releasing its own address. Ignored rather than acted on:
		// a RELEASE is unauthenticated, and honouring one for somebody else's
		// address is a one-packet denial of service against any device on the
		// network.
		return
	}
	p.freeLocked(e, p.clk.Now())
}

// Decline records that a client found the address already in use (RFC 2131
// section 4.3.3).
//
// The address is quarantined rather than freed. Something on this network holds
// it that we do not know about — a device with a static address, or another
// DHCP server — and returning it to the pool produces the same collision for
// the next client, indefinitely.
func (p *Pool) Decline(key string, addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[addr]
	if !ok || e.state == Reserved {
		return
	}
	if e.key != "" && e.key != key {
		return
	}
	delete(p.byKey, e.key)
	*e = entry{addr: addr, state: Declined, freedAt: p.clk.Now()}
}

// Free returns a declined address to the pool, which is the administrator
// action RFC 2131 section 4.3.3 leaves to local policy.
func (p *Pool) Free(addr netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[addr]
	if !ok || e.state != Declined {
		return false
	}
	e.state, e.freedAt = Free, p.clk.Now()
	return true
}

// Lookup returns what the pool remembers about a client key.
//
// The returned lease may have [State] Free: the pool keeps a client's address,
// name and history after its lease lapses, so that a device does not reappear
// as a stranger in the device list on the morning after. Check State before
// treating the address as current — [Pool.LookupAddr] is the call that answers
// "who holds this address right now".
func (p *Pool) Lookup(key string) (Lease, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(p.clk.Now())
	e, ok := p.byKey[key]
	if !ok {
		return Lease{}, false
	}
	return e.lease(), true
}

// LookupAddr returns the client CURRENTLY holding an address.
//
// This is the DNS path's question — "which device is 192.168.4.20?" — asked
// once per query that needs a device identity, and the answer decides which
// policy is applied. So it answers only for a live binding: a leased address
// that has not expired, or a reservation.
//
// An address whose lease has lapsed or been released answers nothing, even
// though the pool still remembers who had it. That memory is for the device
// list, where it is wanted. Using it here would hand the next device to take
// the address the previous one's identity — and with it the previous one's
// rules — so the tablet the household filters would arrive as the laptop it
// does not, and nothing in the UI would look wrong.
func (p *Pool) LookupAddr(addr netip.Addr) (Lease, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[addr]
	if !ok || e.key == "" {
		return Lease{}, false
	}
	switch e.state {
	case Reserved:
		return e.lease(), true
	case Leased:
		if e.lease().Expired(p.clk.Now()) {
			return Lease{}, false
		}
		return e.lease(), true
	default:
		// Free, Offered and Declined. An offered address is not yet in use by
		// the client that was offered it — it is still completing the handshake
		// from 0.0.0.0 — so it identifies nobody either.
		return Lease{}, false
	}
}

// Leases returns every binding the pool knows about, in address order.
//
// Expired bindings are included, marked [Free], because a device list that
// forgot every device the moment its lease lapsed would be empty every morning.
func (p *Pool) Leases() []Lease {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(p.clk.Now())
	out := make([]Lease, 0, len(p.entries))
	for _, e := range p.entries {
		if e.key == "" && e.state == Free {
			continue
		}
		out = append(out, e.lease())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr.Compare(out[j].Addr) < 0 })
	return out
}

// Stats describes pool occupancy, which is what an operator looks at when a
// device will not connect.
type Stats struct {
	Total    int `json:"total"`
	Free     int `json:"free"`
	Leased   int `json:"leased"`
	Offered  int `json:"offered"`
	Declined int `json:"declined"`
	Reserved int `json:"reserved"`
}

// Stats returns occupancy.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expireLocked(p.clk.Now())
	s := Stats{Total: len(p.entries)}
	for _, e := range p.entries {
		switch e.state {
		case Free:
			s.Free++
		case Offered:
			s.Offered++
		case Leased:
			s.Leased++
		case Declined:
			s.Declined++
		case Reserved:
			s.Reserved++
		}
	}
	return s
}

// LeaseTime is how long a lease this pool grants lasts.
func (p *Pool) LeaseTime() time.Duration { return p.lease }

// Subnet is the network this pool serves.
func (p *Pool) Subnet() netip.Prefix { return p.subnet }

// bindLocked attaches a client to an entry and refreshes its timers.
func (p *Pool) bindLocked(e *entry, key string, hw net.HardwareAddr, hostname string, now time.Time, reserved bool) {
	if e.firstSeen.IsZero() {
		e.firstSeen = now
	}
	e.key, e.lastSeen = key, now
	if len(hw) > 0 {
		e.hw = append(net.HardwareAddr(nil), hw...)
	}
	// A client that stops sending a hostname keeps the one it had. Blanking it
	// would empty the device list the first time a phone renewed its lease
	// without repeating option 12, which several do.
	if hostname != "" {
		e.hostname = hostname
	}
	p.byKey[key] = e
	if reserved {
		e.state, e.expires = Reserved, time.Time{}
		return
	}
	e.state = Offered
	e.expires = now.Add(p.offerTTL)
}

// freeLocked returns an entry to the pool, keeping the client's history.
func (p *Pool) freeLocked(e *entry, now time.Time) {
	e.state, e.expires, e.freedAt = Free, time.Time{}, now
}

// availableLocked reports whether key may take this entry.
func (p *Pool) availableLocked(e *entry, key string) bool {
	switch e.state {
	case Free:
		return true
	case Declined:
		return false
	case Reserved:
		return e.key == key
	default:
		return e.key == key
	}
}

// expireLocked frees leases and offers whose time has passed.
//
// A lazy sweep over the whole pool rather than a heap. The pool is at most
// [MaxPoolSize] entries, this runs once per DHCP message rather than once per
// DNS query, and a heap would be a second structure to keep consistent with the
// maps for no measurable gain.
func (p *Pool) expireLocked(now time.Time) {
	for _, e := range p.entries {
		switch e.state {
		case Leased, Offered:
			if !e.expires.IsZero() && !now.Before(e.expires) {
				p.freeLocked(e, e.expires)
			}
		}
	}
}

// leastRecentlyFreedLocked picks the free address unused for longest.
//
// RFC 2131 section 4.3.1 recommends it, and the reason is a user-visible one:
// picking the lowest free address hands a returning device somebody else's old
// address and gives its own away, so a household's addresses shuffle every time
// anyone leaves. Picking the longest-free address keeps them still.
//
// An address that has never been assigned carries the zero time and therefore
// wins over every recycled one. That is deliberate and is the same argument a
// step further: an untouched address belongs to nobody, so spending it costs no
// device its old address, while recycling one that was freed an hour ago may.
func (p *Pool) leastRecentlyFreedLocked() *entry {
	var best *entry
	for _, a := range p.addrs {
		e := p.entries[a]
		if e.state != Free {
			continue
		}
		if best == nil || e.freedAt.Before(best.freedAt) {
			best = e
		}
	}
	return best
}

func orDuration(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// addrDistance counts the addresses from a to b inclusive of neither end.
func addrDistance(a, b netip.Addr) int {
	x, y := a.As4(), b.As4()
	av := uint32(x[0])<<24 | uint32(x[1])<<16 | uint32(x[2])<<8 | uint32(x[3])
	bv := uint32(y[0])<<24 | uint32(y[1])<<16 | uint32(y[2])<<8 | uint32(y[3])
	if bv < av {
		return 0
	}
	d := bv - av
	if d > MaxPoolSize {
		return MaxPoolSize + 1
	}
	return int(d)
}

// broadcastOf returns the all-ones address of a prefix.
func broadcastOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}
