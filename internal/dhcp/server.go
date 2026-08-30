package dhcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/dns/clock"
)

// Well-known ports and addresses, RFC 2131 section 4.1.
var (
	// ServerPort is where clients send and relays forward.
	ServerPort = 67
	// ClientPort is where replies go.
	ClientPort = 68
	// broadcastAddr is the limited broadcast a client with no address can hear.
	broadcastAddr = netip.AddrFrom4([4]byte{255, 255, 255, 255})
)

// ServerOptions configure a [Server].
type ServerOptions struct {
	// Pool allocates the addresses. Required.
	Pool *Pool

	// ServerID is this server's address on the served link — option 54, and
	// the address a client uses to tell one server from another. It must be an
	// address the client can reach us on, so it is the interface's address and
	// not, for instance, a loopback one.
	ServerID netip.Addr

	// Router is the default gateway offered to clients (option 3). Empty omits
	// the option, which is right for a link with no route off it and wrong
	// everywhere else: a client with no router reaches only its own subnet.
	Router netip.Addr

	// DNS are the resolvers offered (option 6). For this product it is this
	// machine, and it is the entire point: it is how a device is told to ask
	// us, and therefore how filtering reaches a device nobody configured.
	DNS []netip.Addr

	// DomainName is option 15, and Search is option 119.
	DomainName string
	Search     []string

	// MTU is option 26. Zero omits it.
	MTU int

	// OnBound is called after every successful binding, with the lease. It is
	// how the device table learns that something joined the network — the one
	// moment a device volunteers its hardware address, its name and its vendor
	// class in a single packet.
	//
	// It runs on the message path, so it must not block. A slow hook here is a
	// device that takes a long time to join the network.
	OnBound func(Lease)

	Clock  clock.Clock
	Logger *slog.Logger
}

// Server answers DHCP messages.
//
// The protocol is implemented in [Server.Handle], which is a function from one
// message to at most one message and touches no socket. That is deliberate:
// everything below is I/O, and everything worth getting wrong — which offer to
// make, when to refuse, where a reply goes — is above it and testable without
// a network, without root and without a device.
type Server struct {
	opts ServerOptions
	pool *Pool
	clk  clock.Clock
	log  *slog.Logger

	mu      sync.Mutex
	conns   []net.PacketConn
	closed  bool
	done    chan struct{}
	wg      sync.WaitGroup
	stats   serverStats
	started bool
}

type serverStats struct {
	received  atomic.Uint64
	malformed atomic.Uint64
	ignored   atomic.Uint64
	offers    atomic.Uint64
	acks      atomic.Uint64
	naks      atomic.Uint64
	declines  atomic.Uint64
	releases  atomic.Uint64
	informs   atomic.Uint64
	writeErrs atomic.Uint64
}

// ServerStats reports what the server has done.
type ServerStats struct {
	Received  uint64 `json:"received"`
	Malformed uint64 `json:"malformed"`
	Ignored   uint64 `json:"ignored"`
	Offers    uint64 `json:"offers"`
	Acks      uint64 `json:"acks"`
	Naks      uint64 `json:"naks"`
	Declines  uint64 `json:"declines"`
	Releases  uint64 `json:"releases"`
	Informs   uint64 `json:"informs"`
	WriteErrs uint64 `json:"write_errors"`
}

// NewServer builds a server.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Pool == nil {
		return nil, errors.New("dhcp: a server needs an address pool")
	}
	if !opts.ServerID.Is4() || opts.ServerID.IsUnspecified() {
		return nil, fmt.Errorf(
			"dhcp: server identifier %v is not a usable IPv4 address; it is what a client uses "+
				"to tell servers apart and must be an address the client can reach us on", opts.ServerID)
	}
	if !opts.Pool.Subnet().Contains(opts.ServerID) {
		return nil, fmt.Errorf("dhcp: server identifier %v is outside the served subnet %v",
			opts.ServerID, opts.Pool.Subnet())
	}
	s := &Server{
		opts: opts,
		pool: opts.Pool,
		clk:  clock.OrSystem(opts.Clock),
		log:  opts.Logger,
		done: make(chan struct{}),
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	return s, nil
}

// Reply is what [Server.Handle] decided to send, and where.
type Reply struct {
	// Message is the reply. Nil means send nothing, which is the correct
	// answer to a RELEASE, a DECLINE, another server's client, and anything
	// malformed.
	Message *Message
	// To is the destination, already resolved through the relay, broadcast and
	// unicast rules of RFC 2131 section 4.1.
	To netip.AddrPort
}

// Handle applies the protocol to one message.
//
// It is pure with respect to the network: no socket, no address of its own
// beyond the configured server identifier, and every effect confined to the
// pool and the OnBound hook. A caller can drive the entire protocol from a
// table of messages, which is how the tests do it.
func (s *Server) Handle(m *Message) Reply {
	// A server answers requests. A message with op=BOOTREPLY is another
	// server's answer, or our own reflected back, and replying to it is how one
	// packet becomes an unbounded exchange between two servers on the same
	// link — the same reflection hazard a DNS server has with QR=1, and it is
	// worth guarding in the same place: before anything else looks at it.
	if m.Op != BootRequest {
		s.stats.ignored.Add(1)
		return Reply{}
	}
	t, ok := m.MessageType()
	if !ok {
		// BOOTP. A BOOTP client will not understand a DHCP reply, and this
		// server has no BOOTP configuration to give it, so answering would be
		// worse than silence.
		s.stats.ignored.Add(1)
		return Reply{}
	}

	switch t {
	case Discover:
		return s.handleDiscover(m)
	case Request:
		return s.handleRequest(m)
	case Decline:
		s.stats.declines.Add(1)
		if a, ok := m.Options.Addr(OptionRequestedIP); ok {
			s.pool.Decline(m.ClientKey(), a)
			s.log.Warn("a client reports its address is already in use",
				slog.String("addr", a.String()),
				slog.String("client", m.CHAddr.String()),
				slog.String("action", "the address is quarantined until an operator frees it"))
		}
		return Reply{}
	case Release:
		s.stats.releases.Add(1)
		if m.CIAddr.Is4() && !m.CIAddr.IsUnspecified() {
			s.pool.Release(m.ClientKey(), m.CIAddr)
		}
		return Reply{}
	case Inform:
		return s.handleInform(m)
	default:
		// OFFER, ACK and NAK are ours to send, not to receive. One arriving
		// with op=BOOTREQUEST is malformed or is probing.
		s.stats.ignored.Add(1)
		return Reply{}
	}
}

func (s *Server) handleDiscover(m *Message) Reply {
	req, _ := m.Options.Addr(OptionRequestedIP)
	lease, err := s.pool.Offer(m.ClientKey(), req, m.CHAddr, m.HostName())
	if err != nil {
		// No OFFER is the RFC's answer to exhaustion: there is nothing to
		// offer, and a NAK would tell the client to restart, which changes
		// nothing. It is logged loudly because it is invisible from the client,
		// which simply never joins the network.
		s.log.Error("no address to offer",
			slog.String("client", m.CHAddr.String()),
			slog.String("host", m.HostName()),
			slog.Any("pool", s.pool.Stats()),
			slog.String("error", err.Error()))
		return Reply{}
	}
	s.stats.offers.Add(1)
	reply := m.Reply(Offer)
	reply.YIAddr = lease.Addr
	s.fill(reply, m, s.pool.LeaseTime())
	return Reply{Message: reply, To: s.destination(m, reply)}
}

func (s *Server) handleRequest(m *Message) Reply {
	key := m.ClientKey()
	kind := m.RequestKind()

	// SELECTING names one server. Every other server must drop its offer and
	// say nothing — answering another server's client is how two DHCP servers
	// on one link produce a device that flips between two addresses.
	if kind == RequestSelecting {
		if id, _ := m.Options.Addr(OptionServerID); id != s.opts.ServerID {
			if l, ok := s.pool.Lookup(key); ok && l.State == Offered {
				s.pool.Release(key, l.Addr)
			}
			s.stats.ignored.Add(1)
			return Reply{}
		}
	}

	var want netip.Addr
	switch kind {
	case RequestSelecting, RequestInitReboot:
		want, _ = m.Options.Addr(OptionRequestedIP)
	case RequestRenewing:
		want = m.CIAddr
	default:
		// RFC 2131 section 4.3.2 defines three shapes and this is none of them.
		// Silence rather than a guess: a NAK would tell a working client to
		// drop a lease it may hold legitimately.
		s.stats.ignored.Add(1)
		return Reply{}
	}

	lease, err := s.pool.Commit(key, want, m.CHAddr, m.HostName())
	if err != nil {
		// RFC 2131 section 4.3.2: NAK, so the client stops using an address it
		// cannot have and restarts. The message option carries the reason,
		// which most clients log — it is the only channel this server has to
		// the person whose device will not connect.
		//
		// One exception: a RENEWING client on a network we do not serve is not
		// ours to NAK. RFC 2131 section 4.3.2 is explicit that a server with no
		// record of a client renewing an address outside its own subnets must
		// stay silent, because the client may be renewing correctly with
		// another server that is simply slower to answer.
		if kind == RequestRenewing && errors.Is(err, ErrNotOurs) {
			s.stats.ignored.Add(1)
			return Reply{}
		}
		s.stats.naks.Add(1)
		nak := m.Reply(Nak)
		nak.Options.SetAddr(OptionServerID, s.opts.ServerID)
		nak.Options.SetString(OptionMessage, err.Error())
		// RFC 2131 section 4.3.2: a NAK carries no address and no lease, and
		// ciaddr must be zero — the client's address is exactly what is being
		// refused.
		nak.CIAddr = netip.Addr{}
		s.log.Info("refused a lease",
			slog.String("client", m.CHAddr.String()),
			slog.String("requested", want.String()),
			slog.String("kind", kind.String()),
			slog.String("reason", err.Error()))
		return Reply{Message: nak, To: s.nakDestination(m)}
	}

	s.stats.acks.Add(1)
	reply := m.Reply(Ack)
	reply.YIAddr = lease.Addr
	// RFC 2131 table 3: ciaddr in an ACK is the client's ciaddr from the
	// REQUEST, which for a renewal is the address it already holds.
	reply.CIAddr = m.CIAddr
	s.fill(reply, m, s.pool.LeaseTime())
	if s.opts.OnBound != nil {
		s.opts.OnBound(lease)
	}
	s.log.Info("bound",
		slog.String("addr", lease.Addr.String()),
		slog.String("client", m.CHAddr.String()),
		slog.String("host", lease.Hostname),
		slog.String("kind", kind.String()))
	return Reply{Message: reply, To: s.destination(m, reply)}
}

// handleInform answers a client that already has an address, RFC 2131 section
// 4.3.5.
//
// It is the interesting case for this product: a device with a static address
// still wants to be told a DNS server, and telling it is how filtering reaches
// a device that never asked us for an address at all. The reply carries
// configuration and NO lease — yiaddr is zero and there is no lease time,
// because nothing was allocated.
func (s *Server) handleInform(m *Message) Reply {
	s.stats.informs.Add(1)
	reply := m.Reply(Ack)
	reply.CIAddr = m.CIAddr
	s.fill(reply, m, 0)
	return Reply{Message: reply, To: s.informDestination(m)}
}

// fill adds the configuration options to a reply.
//
// Options the client asked for in its parameter request list, plus the ones it
// needs whether it asked or not. RFC 2131 section 4.3.1 permits both, and the
// second half matters: a client that requests nothing still has to be told a
// DNS server, or the whole product does nothing for it.
func (s *Server) fill(reply *Message, req *Message, leaseTime time.Duration) {
	reply.Options.SetAddr(OptionServerID, s.opts.ServerID)

	if leaseTime > 0 {
		reply.Options.SetDuration(OptionLeaseTime, leaseTime)
		// T1 and T2, RFC 2131 section 4.4.5. Half and seven-eighths, which is
		// what the RFC suggests and what every client expects: a client that
		// renews at half its lease has the second half to find another server
		// if this one has gone.
		reply.Options.SetDuration(OptionRenewalTime, leaseTime/2)
		reply.Options.SetDuration(OptionRebindingTime, leaseTime*7/8)
	}

	sub := s.pool.Subnet()
	reply.Options.SetAddr(OptionSubnetMask, maskOf(sub))
	reply.Options.SetAddr(OptionBroadcastAddress, broadcastOf(sub))
	if s.opts.Router.Is4() && !s.opts.Router.IsUnspecified() {
		reply.Options.SetAddrs(OptionRouter, []netip.Addr{s.opts.Router})
	}
	if len(s.opts.DNS) > 0 {
		reply.Options.SetAddrs(OptionDNSServer, s.opts.DNS)
	}
	if s.opts.DomainName != "" {
		reply.Options.SetString(OptionDomainName, s.opts.DomainName)
	}
	if len(s.opts.Search) > 0 {
		reply.Options.Set(OptionDomainSearch, encodeSearchList(s.opts.Search))
	}
	if s.opts.MTU > 0 {
		reply.Options.SetUint16(OptionInterfaceMTU, uint16(s.opts.MTU))
	}
	_ = req
}

// destination resolves where a reply goes, RFC 2131 section 4.1.
//
// The order is normative and each branch has a failure attached to getting it
// wrong:
//
//   - Through a relay, if one forwarded the message. The client is not on our
//     link and only the relay can reach it.
//   - Broadcast, if the client asked for one. A client with no address
//     configured cannot always receive a unicast frame, and ignoring the flag
//     is why one particular device never gets a lease while the server's log
//     says it replied.
//   - Unicast to the client's existing address, when it has one — a renewal.
//   - Otherwise broadcast. Strictly RFC 2131 wants a unicast to yiaddr with an
//     ARP entry installed by hand, which a portable UDP socket cannot do; a
//     broadcast reaches the client either way and costs one frame on the link.
func (s *Server) destination(req *Message, reply *Message) netip.AddrPort {
	switch {
	case req.GIAddr.Is4() && !req.GIAddr.IsUnspecified():
		return netip.AddrPortFrom(req.GIAddr, uint16(ServerPort))
	case req.Broadcast():
		return netip.AddrPortFrom(broadcastAddr, uint16(ClientPort))
	case req.CIAddr.Is4() && !req.CIAddr.IsUnspecified():
		return netip.AddrPortFrom(req.CIAddr, uint16(ClientPort))
	default:
		_ = reply
		return netip.AddrPortFrom(broadcastAddr, uint16(ClientPort))
	}
}

// nakDestination is where a refusal goes.
//
// RFC 2131 section 4.3.2 has a NAK broadcast unless it came through a relay:
// the client's address is exactly what is being refused, so unicasting to it
// would send the refusal to an address the client must stop using.
func (s *Server) nakDestination(req *Message) netip.AddrPort {
	if req.GIAddr.Is4() && !req.GIAddr.IsUnspecified() {
		return netip.AddrPortFrom(req.GIAddr, uint16(ServerPort))
	}
	return netip.AddrPortFrom(broadcastAddr, uint16(ClientPort))
}

// informDestination is where an INFORM reply goes: unicast to ciaddr, which
// the client certainly holds because it told us so and is using it.
func (s *Server) informDestination(req *Message) netip.AddrPort {
	if req.GIAddr.Is4() && !req.GIAddr.IsUnspecified() {
		return netip.AddrPortFrom(req.GIAddr, uint16(ServerPort))
	}
	if req.CIAddr.Is4() && !req.CIAddr.IsUnspecified() {
		return netip.AddrPortFrom(req.CIAddr, uint16(ClientPort))
	}
	return netip.AddrPortFrom(broadcastAddr, uint16(ClientPort))
}

// Serve answers on pc until [Server.Close].
//
// The socket is the caller's: it opens it, it closes it, and it decides which
// interface it is bound to. Port 67 is privileged and binding it to one
// interface needs a platform-specific option, both of which belong above this
// package — the same rule the engine follows for its listeners, and for the
// same reason, which is that a component that opens its own sockets cannot be
// run by a process that has already dropped its privileges.
func (s *Server) Serve(pc net.PacketConn) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.conns = append(s.conns, pc)
	s.started = true
	s.wg.Add(1)
	s.mu.Unlock()
	defer s.wg.Done()

	buf := make([]byte, 4096)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.done:
				return nil
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("dhcp: reading: %w", err)
		}
		s.stats.received.Add(1)
		s.serveOne(pc, buf[:n], from)
	}
}

// serveOne handles one datagram. It runs on the read loop rather than on a
// goroutine of its own: DHCP is a handful of messages per device per lease
// period, and serialising them means the pool's decisions happen in the order
// the packets arrived, which is what makes a duplicated DISCOVER idempotent.
func (s *Server) serveOne(pc net.PacketConn, wire []byte, from net.Addr) {
	// Guarded before decoding, like the reflection check in Handle. A reply
	// arriving on port 67 is another server or our own packet coming back, and
	// deciding that after a parse means a malformed one still reaches the
	// handler.
	if len(wire) >= 1 && OpCode(wire[0]) != BootRequest {
		s.stats.ignored.Add(1)
		return
	}
	m, err := Unpack(wire)
	if err != nil {
		s.stats.malformed.Add(1)
		s.log.Debug("discarded a malformed message",
			slog.String("from", from.String()),
			slog.Int("octets", len(wire)),
			slog.String("error", err.Error()))
		return
	}

	reply := s.handleRecovered(m)
	if reply.Message == nil {
		return
	}
	out, err := reply.Message.Pack()
	if err != nil {
		s.log.Error("could not encode a reply", slog.String("error", err.Error()))
		return
	}
	if len(out) > m.MaxSize() {
		// The client told us what it can accept and this does not fit. Sending
		// it anyway produces a reply the client discards, which looks from here
		// like a successful lease and from there like nothing at all.
		s.log.Warn("reply exceeds the client's maximum message size",
			slog.Int("octets", len(out)), slog.Int("max", m.MaxSize()),
			slog.String("client", m.CHAddr.String()))
	}
	if _, err := pc.WriteTo(out, net.UDPAddrFromAddrPort(reply.To)); err != nil {
		s.stats.writeErrs.Add(1)
		s.log.Warn("could not send a reply",
			slog.String("to", reply.To.String()),
			slog.String("error", err.Error()))
	}
}

// handleRecovered runs Handle with a recover.
//
// The pool decides who is allowed on the network, and a panic on this path
// takes the whole application down with it — including the DNS server, so a bug
// reachable from one malformed DHCP packet would cost every device on the
// network its name resolution. One device failing to get a lease is a much
// smaller loss than that.
func (s *Server) handleRecovered(m *Message) (r Reply) {
	defer func() {
		if v := recover(); v != nil {
			s.log.Error("panic while handling a DHCP message",
				slog.Any("panic", v), slog.String("message", m.String()))
			r = Reply{}
		}
	}()
	return s.Handle(m)
}

// Close stops serving. It does not close the sockets, which belong to the
// caller — but it does unblock the read loops, so a caller may close them
// immediately afterwards.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	close(s.done)
	conns := s.conns
	s.mu.Unlock()

	// A read deadline in the past, rather than closing the socket: the socket
	// is the caller's, and this is how a read blocked in the kernel is
	// interrupted without taking it away from them.
	for _, c := range conns {
		_ = c.SetReadDeadline(time.Now().Add(-time.Second))
	}
	s.wg.Wait()
	return nil
}

// Shutdown stops serving, waiting for the read loops or for ctx.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan error, 1)
	go func() { done <- s.Close() }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Stats returns a snapshot.
func (s *Server) Stats() ServerStats {
	return ServerStats{
		Received:  s.stats.received.Load(),
		Malformed: s.stats.malformed.Load(),
		Ignored:   s.stats.ignored.Load(),
		Offers:    s.stats.offers.Load(),
		Acks:      s.stats.acks.Load(),
		Naks:      s.stats.naks.Load(),
		Declines:  s.stats.declines.Load(),
		Releases:  s.stats.releases.Load(),
		Informs:   s.stats.informs.Load(),
		WriteErrs: s.stats.writeErrs.Load(),
	}
}

// maskOf returns a prefix's netmask as an address.
func maskOf(p netip.Prefix) netip.Addr {
	var v uint32
	if p.Bits() > 0 {
		v = ^uint32(0) << (32 - p.Bits())
	}
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// encodeSearchList encodes option 119, RFC 3397.
//
// Uncompressed. RFC 3397 permits the compression of RFC 1035 section 4.1.4
// within the option, and several clients get it wrong; the saving on a
// household's one or two search domains is a few octets against a client that
// silently fails to parse the option.
func encodeSearchList(names []string) []byte {
	var out []byte
	for _, n := range names {
		for label := range splitLabels(n) {
			if len(label) == 0 || len(label) > 63 {
				continue
			}
			out = append(out, byte(len(label)))
			out = append(out, label...)
		}
		out = append(out, 0)
	}
	return out
}

func splitLabels(name string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for len(name) > 0 {
			i := 0
			for i < len(name) && name[i] != '.' {
				i++
			}
			if !yield(name[:i]) {
				return
			}
			if i == len(name) {
				return
			}
			name = name[i+1:]
		}
	}
}
