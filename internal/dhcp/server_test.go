package dhcp

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/dns/clock"
)

var (
	serverAddr = addr("192.168.4.1")
	dnsAddr    = addr("192.168.4.1")
)

func testServer(t testing.TB, mutate func(*ServerOptions)) (*Server, *Pool, *clock.Fake) {
	t.Helper()
	p, fake := testPool(t, nil)
	opts := ServerOptions{
		Pool:       p,
		ServerID:   serverAddr,
		Router:     serverAddr,
		DNS:        []netip.Addr{dnsAddr},
		DomainName: "lan",
		MTU:        1500,
		Clock:      fake,
	}
	if mutate != nil {
		mutate(&opts)
	}
	s, err := NewServer(opts)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, p, fake
}

// A DISCOVER is answered with an OFFER carrying everything a client needs to
// configure itself, including the options it did not think to ask for.
func TestDiscoverIsOffered(t *testing.T) {
	t.Parallel()
	s, p, _ := testServer(t, nil)

	// A client that requests nothing at all. It still has to be told a DNS
	// server, or the whole product does nothing for it.
	m := discover()
	m.Options.Delete(OptionParameterRequestList)

	r := s.Handle(m)
	if r.Message == nil {
		t.Fatal("no reply to a DISCOVER")
	}
	if got, _ := r.Message.MessageType(); got != Offer {
		t.Errorf("message type = %v, want OFFER", got)
	}
	if !p.Subnet().Contains(r.Message.YIAddr) {
		t.Errorf("offered %v, which is outside %v", r.Message.YIAddr, p.Subnet())
	}
	for _, tc := range []struct {
		code OptionCode
		want string
	}{
		{OptionServerID, "192.168.4.1"},
		{OptionSubnetMask, "255.255.255.0"},
		{OptionRouter, "192.168.4.1"},
		{OptionDNSServer, "192.168.4.1"},
		{OptionBroadcastAddress, "192.168.4.255"},
	} {
		got, ok := r.Message.Options.Addrs(tc.code)
		if !ok || len(got) == 0 {
			t.Errorf("%s is missing from the offer", tc.code)
			continue
		}
		if got[0].String() != tc.want {
			t.Errorf("%s = %v, want %s", tc.code, got[0], tc.want)
		}
	}
	if got, _ := r.Message.Options.String(OptionDomainName); got != "lan" {
		t.Errorf("domain name = %q", got)
	}
	if got, _ := r.Message.Options.Uint16(OptionInterfaceMTU); got != 1500 {
		t.Errorf("MTU = %d", got)
	}

	// An offer holds the address but does not bind it: the client has not
	// accepted, and the address must not identify it yet.
	if _, ok := p.LookupAddr(r.Message.YIAddr); ok {
		t.Error("an offered address already identifies the client")
	}
}

// RFC 2131 section 4.4.5: renew at half the lease, rebind at seven-eighths. A
// client that renews at half has the second half to find another server if this
// one has gone.
func TestRenewalTimersFollowTheLease(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)
	r := s.Handle(discover())

	lease, ok := r.Message.Options.Duration(OptionLeaseTime)
	if !ok {
		t.Fatal("no lease time in the offer")
	}
	t1, ok1 := r.Message.Options.Duration(OptionRenewalTime)
	t2, ok2 := r.Message.Options.Duration(OptionRebindingTime)
	if !ok1 || !ok2 {
		t.Fatal("T1 or T2 is missing")
	}
	if t1 != lease/2 {
		t.Errorf("T1 = %v, want half of %v", t1, lease)
	}
	if t2 != lease*7/8 {
		t.Errorf("T2 = %v, want seven-eighths of %v", t2, lease)
	}
}

// Answering another server's client is how two DHCP servers on one link produce
// a device that flips between two addresses.
func TestSelectingAnotherServerIsAnsweredWithSilence(t *testing.T) {
	t.Parallel()
	s, p, _ := testServer(t, nil)

	offer := s.Handle(discover())
	offered := offer.Message.YIAddr

	req := discover()
	req.SetMessageType(Request)
	req.Options.SetAddr(OptionServerID, addr("192.168.4.99")) // not us
	req.Options.SetAddr(OptionRequestedIP, offered)

	if r := s.Handle(req); r.Message != nil {
		t.Fatalf("answered a client that selected another server: %v", r.Message)
	}
	// And our offer is dropped, so the address is not held for a client that
	// has gone elsewhere.
	if st := p.Stats(); st.Offered != 0 {
		t.Errorf("stats = %+v, want the offer released", st)
	}
}

func TestSelectingUsIsAcknowledged(t *testing.T) {
	t.Parallel()
	var bound []Lease
	var mu sync.Mutex
	s, p, _ := testServer(t, func(o *ServerOptions) {
		o.OnBound = func(l Lease) { mu.Lock(); bound = append(bound, l); mu.Unlock() }
	})

	offer := s.Handle(discover())
	offered := offer.Message.YIAddr

	req := discover()
	req.SetMessageType(Request)
	req.Options.SetAddr(OptionServerID, serverAddr)
	req.Options.SetAddr(OptionRequestedIP, offered)

	r := s.Handle(req)
	if r.Message == nil {
		t.Fatal("no reply to a REQUEST that selected us")
	}
	if got, _ := r.Message.MessageType(); got != Ack {
		t.Fatalf("message type = %v, want ACK", got)
	}
	if r.Message.YIAddr != offered {
		t.Errorf("acknowledged %v, having offered %v", r.Message.YIAddr, offered)
	}
	// Now, and only now, the address identifies the device.
	l, ok := p.LookupAddr(offered)
	if !ok || l.Hostname != "pixel" {
		t.Errorf("LookupAddr = %+v %v, want the bound client", l, ok)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(bound) != 1 {
		t.Fatalf("OnBound fired %d times, want once — it is how the device table learns", len(bound))
	}
	if bound[0].Addr != offered || bound[0].Hostname != "pixel" {
		t.Errorf("OnBound got %+v", bound[0])
	}
}

// An OFFER must not fire OnBound: nothing is bound until the client accepts,
// and a device table that listed every offer would list devices that never
// joined.
func TestOnBoundDoesNotFireForAnOffer(t *testing.T) {
	t.Parallel()
	var fired int
	s, _, _ := testServer(t, func(o *ServerOptions) { o.OnBound = func(Lease) { fired++ } })
	s.Handle(discover())
	if fired != 0 {
		t.Errorf("OnBound fired %d times for an offer", fired)
	}
}

// RFC 2131 section 4.3.2: a client asking for an address it cannot have is
// NAKed so that it stops using it and restarts. The NAK carries no address, no
// lease and no ciaddr — the client's address is exactly what is being refused.
func TestARefusalIsANakWithAReason(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)

	// Somebody else holds it.
	held := s.Handle(discover())
	sel := discover()
	sel.SetMessageType(Request)
	sel.Options.SetAddr(OptionServerID, serverAddr)
	sel.Options.SetAddr(OptionRequestedIP, held.Message.YIAddr)
	s.Handle(sel)

	thief := discover()
	thief.CHAddr = net.HardwareAddr{0x02, 9, 9, 9, 9, 9}
	thief.Options.Delete(OptionClientID)
	thief.SetMessageType(Request)
	thief.Options.SetAddr(OptionServerID, serverAddr)
	thief.Options.SetAddr(OptionRequestedIP, held.Message.YIAddr)

	r := s.Handle(thief)
	if r.Message == nil {
		t.Fatal("no reply to a request for another client's address")
	}
	if got, _ := r.Message.MessageType(); got != Nak {
		t.Fatalf("message type = %v, want NAK", got)
	}
	if r.Message.YIAddr.IsValid() && !r.Message.YIAddr.IsUnspecified() {
		t.Errorf("the NAK carries an address, %v", r.Message.YIAddr)
	}
	if r.Message.CIAddr.IsValid() && !r.Message.CIAddr.IsUnspecified() {
		t.Errorf("the NAK carries a ciaddr, %v", r.Message.CIAddr)
	}
	if r.Message.Options.Has(OptionLeaseTime) {
		t.Error("the NAK carries a lease time")
	}
	// The message option is the only channel this server has to the person
	// whose device will not connect.
	if msg, ok := r.Message.Options.String(OptionMessage); !ok || msg == "" {
		t.Error("the NAK says nothing about why")
	}
	// And it is broadcast: unicasting a refusal to the address being refused
	// sends it to an address the client must stop using.
	if r.To.Addr() != broadcastAddr || r.To.Port() != uint16(ClientPort) {
		t.Errorf("NAK destination = %v, want a broadcast to the client port", r.To)
	}
}

// RFC 2131 section 4.3.2: a server with no record of a client renewing an
// address outside its own subnets must stay silent. The client may be renewing
// correctly with another server that is simply slower to answer.
func TestRenewalForAnotherNetworkIsNotNaked(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)

	m := discover()
	m.SetMessageType(Request)
	m.CIAddr = addr("10.9.9.9")

	if r := s.Handle(m); r.Message != nil {
		got, _ := r.Message.MessageType()
		t.Errorf("answered a foreign renewal with %v; it belongs to another server", got)
	}
}

// An INIT-REBOOT client remembering an address from another network must be
// NAKed, so it stops using an address that will not route here.
func TestInitRebootOnTheWrongNetworkIsNaked(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)

	m := discover()
	m.SetMessageType(Request)
	m.Options.SetAddr(OptionRequestedIP, addr("10.9.9.9"))

	r := s.Handle(m)
	if r.Message == nil {
		t.Fatal("no reply to an INIT-REBOOT for a foreign address")
	}
	if got, _ := r.Message.MessageType(); got != Nak {
		t.Errorf("message type = %v, want NAK", got)
	}
}

func TestReleaseAndDeclineChangeThePool(t *testing.T) {
	t.Parallel()
	s, p, _ := testServer(t, nil)

	offer := s.Handle(discover())
	sel := discover()
	sel.SetMessageType(Request)
	sel.Options.SetAddr(OptionServerID, serverAddr)
	sel.Options.SetAddr(OptionRequestedIP, offer.Message.YIAddr)
	s.Handle(sel)

	rel := discover()
	rel.SetMessageType(Release)
	rel.CIAddr = offer.Message.YIAddr
	if r := s.Handle(rel); r.Message != nil {
		t.Error("a RELEASE was answered; RFC 2131 has no reply to one")
	}
	if _, ok := p.LookupAddr(offer.Message.YIAddr); ok {
		t.Error("the address is still bound after a RELEASE")
	}

	dec := discover()
	dec.SetMessageType(Decline)
	dec.Options.SetAddr(OptionRequestedIP, offer.Message.YIAddr)
	if r := s.Handle(dec); r.Message != nil {
		t.Error("a DECLINE was answered")
	}
	if st := p.Stats(); st.Declined != 1 {
		t.Errorf("stats = %+v, want the declined address quarantined", st)
	}
}

// RFC 2131 section 4.3.5. This is how filtering reaches a device that never
// asked us for an address at all.
func TestInformIsAnsweredWithConfigurationAndNoLease(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)

	m := discover()
	m.SetMessageType(Inform)
	m.CIAddr = addr("192.168.4.77")
	m.SetBroadcast(false)

	r := s.Handle(m)
	if r.Message == nil {
		t.Fatal("no reply to an INFORM")
	}
	if got, _ := r.Message.MessageType(); got != Ack {
		t.Errorf("message type = %v, want ACK", got)
	}
	if r.Message.YIAddr.IsValid() && !r.Message.YIAddr.IsUnspecified() {
		t.Errorf("the reply allocates %v; an INFORM allocates nothing", r.Message.YIAddr)
	}
	if r.Message.Options.Has(OptionLeaseTime) {
		t.Error("the reply carries a lease time; nothing was leased")
	}
	if dns, ok := r.Message.Options.Addrs(OptionDNSServer); !ok || dns[0] != dnsAddr {
		t.Error("the reply does not name a DNS server, which is the only reason to answer an INFORM")
	}
	// Unicast to the address the client told us it is using.
	if r.To.Addr() != m.CIAddr {
		t.Errorf("destination = %v, want the client's own address", r.To)
	}
}

// Replying to a reply is how one packet becomes an unbounded exchange between
// two servers on the same link. It is the same hazard a DNS server has with
// QR=1 and is guarded in the same place: before anything else looks at it.
func TestNeverRepliesToAReply(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)

	// A well-formed message that happens to be a reply. This is the case that
	// matters: a guard that only caught malformed input would pass a test and
	// leave the property broken.
	m := discover()
	m.Op = BootReply
	m.SetMessageType(Offer)
	if r := s.Handle(m); r.Message != nil {
		t.Fatal("answered a BOOTREPLY; two servers on one link would answer each other forever")
	}

	// Also over the socket path, where the guard sits before the decode.
	ack := discover()
	ack.Op = BootReply
	ack.SetMessageType(Ack)
	conn := newFakeConn()
	go func() { _ = s.Serve(conn) }()
	conn.deliver(mustPack(t, ack), netip.AddrPortFrom(addr("192.168.4.20"), 68))
	conn.deliver([]byte{byte(BootReply), 1, 2, 3}, netip.AddrPortFrom(addr("192.168.4.20"), 68))
	time.Sleep(50 * time.Millisecond)
	if got := conn.sent(); len(got) != 0 {
		t.Errorf("the server sent %d replies to replies", len(got))
	}
}

// A BOOTP client will not understand a DHCP reply, and this server has no BOOTP
// configuration to give it, so answering is worse than silence.
func TestBootpIsIgnored(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)
	m := discover()
	m.Options.Delete(OptionMessageType)
	if r := s.Handle(m); r.Message != nil {
		t.Error("answered a BOOTP request")
	}
}

// The destination rules of RFC 2131 section 4.1, each of which has a failure
// attached to getting it wrong.
func TestReplyDestinations(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, nil)
	relay := addr("192.168.4.250")

	for _, tc := range []struct {
		name  string
		build func(*Message)
		want  netip.AddrPort
	}{
		{"through a relay", func(m *Message) {
			m.GIAddr = relay
			m.SetBroadcast(true)
		}, netip.AddrPortFrom(relay, uint16(ServerPort))},
		{"broadcast requested", func(m *Message) {
			m.SetBroadcast(true)
		}, netip.AddrPortFrom(broadcastAddr, uint16(ClientPort))},
		{"renewing client", func(m *Message) {
			m.SetBroadcast(false)
			m.CIAddr = addr("192.168.4.15")
		}, netip.AddrPortFrom(addr("192.168.4.15"), uint16(ClientPort))},
		{"no address yet", func(m *Message) {
			m.SetBroadcast(false)
		}, netip.AddrPortFrom(broadcastAddr, uint16(ClientPort))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := discover()
			m.CHAddr = net.HardwareAddr{0x02, 0, 0, 0, byte(len(tc.name)), 1}
			m.Options.Set(OptionClientID, []byte(tc.name))
			tc.build(m)
			r := s.Handle(m)
			if r.Message == nil {
				t.Fatal("no reply")
			}
			if r.To != tc.want {
				t.Errorf("destination = %v, want %v", r.To, tc.want)
			}
		})
	}
}

// A panic on this path would take the DNS server down with it, so every device
// on the network would lose name resolution because one DHCP packet was odd.
// One device failing to get a lease is a much smaller loss.
func TestAPanicCostsOneMessageNotTheProcess(t *testing.T) {
	t.Parallel()
	s, _, _ := testServer(t, func(o *ServerOptions) {
		o.OnBound = func(Lease) { panic("a hook somebody wrote downstream") }
	})
	conn := newFakeConn()
	go func() { _ = s.Serve(conn) }()

	offer := s.Handle(discover())
	sel := discover()
	sel.SetMessageType(Request)
	sel.Options.SetAddr(OptionServerID, serverAddr)
	sel.Options.SetAddr(OptionRequestedIP, offer.Message.YIAddr)
	conn.deliver(mustPack(t, sel), netip.AddrPortFrom(addr("0.0.0.0"), 68))

	// Still serving afterwards.
	time.Sleep(50 * time.Millisecond)
	conn.deliver(mustPack(t, discover()), netip.AddrPortFrom(addr("0.0.0.0"), 68))
	deadline := time.Now().Add(5 * time.Second)
	for len(conn.sent()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the server stopped answering after a panic in a hook")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The whole exchange over a socket, which is what a device actually does.
func TestServeCompletesAnExchange(t *testing.T) {
	t.Parallel()
	s, p, _ := testServer(t, nil)
	conn := newFakeConn()
	served := make(chan error, 1)
	go func() { served <- s.Serve(conn) }()

	conn.deliver(mustPack(t, discover()), netip.AddrPortFrom(addr("0.0.0.0"), 68))
	out := conn.await(t, 1)
	offer, err := Unpack(out[0].data)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := offer.MessageType(); got != Offer {
		t.Fatalf("first reply is %v, want OFFER", got)
	}

	req := discover()
	req.SetMessageType(Request)
	req.Options.SetAddr(OptionServerID, serverAddr)
	req.Options.SetAddr(OptionRequestedIP, offer.YIAddr)
	conn.deliver(mustPack(t, req), netip.AddrPortFrom(addr("0.0.0.0"), 68))
	out = conn.await(t, 2)
	ack, err := Unpack(out[1].data)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := ack.MessageType(); got != Ack {
		t.Fatalf("second reply is %v, want ACK", got)
	}
	if _, ok := p.LookupAddr(ack.YIAddr); !ok {
		t.Error("the exchange completed but nothing is bound")
	}

	// Malformed input is counted, not fatal.
	conn.deliver([]byte{1, 2, 3}, netip.AddrPortFrom(addr("0.0.0.0"), 68))
	time.Sleep(50 * time.Millisecond)
	if s.Stats().Malformed == 0 {
		t.Error("a malformed datagram was not counted")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Shutdown(ctx); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if err := <-served; err != nil {
		t.Errorf("Serve: %v", err)
	}
}

func TestServerConstructionIsChecked(t *testing.T) {
	t.Parallel()
	p, _ := testPool(t, nil)
	for _, tc := range []struct {
		name string
		opts ServerOptions
		want string
	}{
		{"no pool", ServerOptions{ServerID: serverAddr}, "address pool"},
		{"no server id", ServerOptions{Pool: p}, "server identifier"},
		{"server id off the link", ServerOptions{Pool: p, ServerID: addr("10.0.0.1")}, "outside the served subnet"},
	} {
		if _, err := NewServer(tc.opts); err == nil {
			t.Errorf("%s was accepted", tc.name)
		} else if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %q, want it to mention %q", tc.name, err, tc.want)
		}
	}
}

// fakeConn is a net.PacketConn with no network behind it.
//
// The alternative is a real socket, which for DHCP means port 67, a broadcast
// address and root — none of which belongs in a unit test, and all of which
// would make the protocol untestable on a laptop and in CI.
type fakeConn struct {
	mu       sync.Mutex
	in       chan datagram
	out      []datagram
	closed   bool
	deadline time.Time
	// wake exists because a deadline set AFTER a read has blocked must still
	// interrupt it — that is how a real socket behaves, and it is the mechanism
	// Server.Close relies on to stop a read loop without taking the caller's
	// socket away. A fake that only honoured a deadline set beforehand would
	// hang the very shutdown it is meant to exercise.
	wake chan struct{}
}

type datagram struct {
	data []byte
	from netip.AddrPort
}

func newFakeConn() *fakeConn {
	return &fakeConn{in: make(chan datagram, 16), wake: make(chan struct{}, 1)}
}

func (c *fakeConn) deliver(b []byte, from netip.AddrPort) {
	c.in <- datagram{data: append([]byte(nil), b...), from: from}
}

func (c *fakeConn) sent() []datagram {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]datagram(nil), c.out...)
}

func (c *fakeConn) await(t testing.TB, n int) []datagram {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := c.sent(); len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d replies were sent", len(c.sent()), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (c *fakeConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		d, closed := c.deadline, c.closed
		c.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		var timer <-chan time.Time
		if !d.IsZero() {
			wait := time.Until(d)
			if wait <= 0 {
				return 0, nil, timeoutError{}
			}
			t := time.NewTimer(wait)
			timer = t.C
			defer t.Stop()
		}
		select {
		case dg, ok := <-c.in:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return copy(p, dg.data), net.UDPAddrFromAddrPort(dg.from), nil
		case <-timer:
			return 0, nil, timeoutError{}
		case <-c.wake:
			// A deadline or a close landed while this read was blocked. Round
			// the loop and re-read both.
		}
	}
}

func (c *fakeConn) WriteTo(p []byte, a net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ap, _ := netip.ParseAddrPort(a.String())
	c.out = append(c.out, datagram{data: append([]byte(nil), p...), from: ap})
	return len(p), nil
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	c.signal()
	return nil
}

func (c *fakeConn) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}
func (c *fakeConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero, Port: ServerPort} }
func (c *fakeConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}
func (c *fakeConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	c.signal()
	return nil
}
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
