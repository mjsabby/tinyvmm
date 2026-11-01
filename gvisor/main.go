// Command tinyvmm_gvisor builds tinyvmm_gvisor.dll, gVisor's netstack as a
// user-mode NAT for tinyvmm's virtio-net (`--net-backend gvisor`).
//
// tinyvmm hands guest Ethernet frames to tvg_input and gets the frames for
// the guest through the send callback it registers with tvg_new. The stack
// owns the gateway address and accepts every other destination too
// (promiscuous, spoofing): a TCP forwarder answers a guest SYN only once the
// host connection succeeds (else it resets the guest's), then relays both
// ways; a UDP forwarder relays datagrams per 4-tuple. Connections to the
// gateway reach the host's loopback, as with tinyvmm's own NAT. DHCP and
// ICMP to hosts other than the gateway are tinyvmm's business (src/net/gvisor.rs).
//
// Frames to the guest leave as gVisor builds them with host GSO: TCP
// segments up to ~64 KiB with a partial checksum, described to the guest by
// a virtio-net header. Frames from the guest may be TSO super-segments with
// unfinished checksums, which gVisor doesn't check (see linkEP.Capabilities).
//
// Build (needs cgo, i.e. a MinGW-w64 gcc or `zig cc` as CC): see build.ps1.
package main

/*
#include <stdint.h>

// One frame for the guest. gso_mss > 0: a TCPv4 GSO frame of segments of
// that size; needs_csum: the TCP checksum holds only the pseudo-header sum,
// and the L4 header starts l3_len bytes after the Ethernet header; more:
// another frame of the same batch follows.
typedef void (*tvg_send_fn)(void *ctx, const uint8_t *frame, int32_t len,
                            int32_t gso_mss, int32_t needs_csum, int32_t l3_len,
                            int32_t more);

static inline void tvg_call_send(tvg_send_fn f, void *ctx, const uint8_t *frame,
                                 int32_t len, int32_t gso_mss, int32_t needs_csum,
                                 int32_t l3_len, int32_t more) {
	f(ctx, frame, len, gso_mss, needs_csum, l3_len, more);
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"runtime/cgo"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

func main() {}

// TINYVMM_GVISOR_DEBUG=1 prints the stack's nonzero counters to stderr when it
// closes; 2 also logs each connection it handles.
var debugLevel = func() int {
	switch os.Getenv("TINYVMM_GVISOR_DEBUG") {
	case "", "0":
		return 0
	case "1":
		return 1
	}
	return 2
}()

func debugf(format string, args ...any) {
	if debugLevel >= 2 {
		fmt.Fprintf(os.Stderr, "[gvisor] "+format+"\n", args...)
	}
}

// At debug level 1, each forwarded connection's progress is kept in memory
// (logging it would change the timing being debugged): connections that
// never finished, and stages that took over a second, are printed at close.
type stageMark struct {
	stage string
	at    time.Time
}

var (
	stages   sync.Map // connection name -> stageMark
	slowMu   sync.Mutex
	slowLogs []string
)

func markStage(name, stage string) {
	if debugLevel < 1 {
		return
	}
	now := time.Now()
	if prev, ok := stages.Load(name); ok {
		p := prev.(stageMark)
		if d := now.Sub(p.at); d > time.Second {
			slowMu.Lock()
			slowLogs = append(slowLogs, fmt.Sprintf("%s: %s took %v", name, p.stage, d))
			slowMu.Unlock()
		}
	}
	if stage == "" {
		stages.Delete(name)
	} else {
		stages.Store(name, stageMark{stage, now})
	}
}

func dumpStages() {
	slowMu.Lock()
	for _, l := range slowLogs {
		fmt.Fprintf(os.Stderr, "[gvisor] slow %s\n", l)
	}
	slowMu.Unlock()
	stages.Range(func(k, v any) bool {
		m := v.(stageMark)
		fmt.Fprintf(os.Stderr, "[gvisor] unfinished %s: %s for %v\n", k, m.stage, time.Since(m.at))
		return true
	})
}

// dumpCounters prints every nonzero counter reachable from v (a gVisor stats
// struct) as name=value lines.
func dumpCounters(name string, v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		if c, ok := v.Interface().(*tcpip.StatCounter); ok {
			if n := c.Value(); n != 0 {
				fmt.Fprintf(os.Stderr, "[gvisor] %s=%d\n", name, n)
			}
			return
		}
		dumpCounters(name, v.Elem())
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			if t.Field(i).IsExported() {
				dumpCounters(name+"."+t.Field(i).Name, v.Field(i))
			}
		}
	case reflect.Array, reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			dumpCounters(fmt.Sprintf("%s[%d]", name, i), v.Index(i))
		}
	}
}

const (
	nicID = 1
	// Most guest frames waiting for the stack; more are dropped.
	inputQueue = 4096
	// Largest GSO packet built for the guest (IP header included), within
	// the IPv4 total length and tinyvmm's RX frame slots.
	gsoMaxSize = 62 * 1024
	// The host-side connect deadline, as tinyvmm's NAT (TCP_CONNECT_MS).
	connectTimeout = 10 * time.Second
	// A UDP flow idle this long is dropped, as tinyvmm's NAT (UDP_IDLE_MS).
	udpIdle = 60 * time.Second
	// Relay buffer per direction (tinyvmm's NAT receives up to 256 KiB).
	relayBuf = 256 * 1024
)

// linkEP is the stack's NIC: inbound frames come from tvg_input, outbound
// ones go to tinyvmm's send callback. ethernet.New wraps it, so frames here
// include their Ethernet header.
type linkEP struct {
	send C.tvg_send_fn
	ctx  unsafe.Pointer

	// Held for reading across each send callback; tvg_close takes it for
	// writing, so once it returns tinyvmm hears nothing more.
	mu         sync.RWMutex
	closed     bool
	dispatcher stack.NetworkDispatcher
	mtu        uint32
	mac        tcpip.LinkAddress

	in   chan *stack.PacketBuffer
	done chan struct{}
	bufs sync.Pool
}

var _ stack.LinkEndpoint = (*linkEP)(nil)
var _ stack.GSOEndpoint = (*linkEP)(nil)

func (e *linkEP) MTU() uint32 {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mtu
}
func (e *linkEP) SetMTU(mtu uint32) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mtu = mtu
}
func (*linkEP) MaxHeaderLength() uint16 { return 0 }
func (e *linkEP) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mac
}
func (e *linkEP) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.mac = addr
}

// The guest's kernel is the only sender on the link, and it leaves the L4
// checksums of offloaded frames to the host: gVisor checks none (its NIC
// applies this per link, not per packet).
func (*linkEP) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityRXChecksumOffload
}
func (e *linkEP) Attach(d stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = d
}
func (e *linkEP) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}
func (*linkEP) Wait()                                   {}
func (*linkEP) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareNone }
func (*linkEP) AddHeader(*stack.PacketBuffer)           {}
func (*linkEP) ParseHeader(*stack.PacketBuffer) bool    { return true }
func (*linkEP) Close()                                  {}
func (*linkEP) SetOnCloseAction(func())                 {}
func (*linkEP) GSOMaxSize() uint32                      { return gsoMaxSize }
func (*linkEP) SupportedGSO() stack.SupportedGSO        { return stack.HostGSOSupported }

// WritePackets hands each packet to tinyvmm, flattened into one buffer.
func (e *linkEP) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return 0, &tcpip.ErrClosedForSend{}
	}
	all := pkts.AsSlice()
	for i, pkt := range all {
		bp := e.bufs.Get().(*[]byte)
		b := (*bp)[:0]
		for _, s := range pkt.AsSlices() {
			b = append(b, s...)
		}
		var mss, csum, l3 C.int32_t
		g := pkt.GSOOptions
		if g.Type == stack.GSOTCPv4 && pkt.Data().Size() > int(g.MSS) {
			mss = C.int32_t(g.MSS)
		}
		if g.Type != stack.GSONone && g.NeedsCsum {
			csum, l3 = 1, C.int32_t(g.L3HdrLen)
		}
		more := C.int32_t(0)
		if i+1 < len(all) {
			more = 1
		}
		if len(b) > 0 {
			C.tvg_call_send(e.send, e.ctx, (*C.uint8_t)(unsafe.Pointer(&b[0])),
				C.int32_t(len(b)), mss, csum, l3, more)
		}
		*bp = b
		e.bufs.Put(bp)
	}
	return len(all), nil
}

// deliver feeds queued guest frames to the stack, in order.
func (e *linkEP) deliver() {
	for {
		select {
		case pkt := <-e.in:
			e.mu.RLock()
			d := e.dispatcher
			e.mu.RUnlock()
			if d != nil {
				d.DeliverNetworkPacket(0, pkt)
			}
			pkt.DecRef()
		case <-e.done:
			return
		}
	}
}

type portForward struct {
	l net.Listener
}

type natStack struct {
	s       *stack.Stack
	ep      *linkEP
	gateway tcpip.Address

	mu        sync.Mutex
	forwards  []portForward
	closeOnce sync.Once
	closed    atomic.Bool

	inputDrops atomic.Uint64
	tcpRefused atomic.Uint64
	tcpFlows   atomic.Uint64
	udpFlows   atomic.Uint64
}

// hostAddr is where a guest connection to ip:port goes on the host: the
// gateway is the host's loopback.
func (n *natStack) hostAddr(ip tcpip.Address, port uint16) string {
	a := netip.AddrFrom4(ip.As4())
	if ip == n.gateway {
		a = netip.AddrFrom4([4]byte{127, 0, 0, 1})
	}
	return netip.AddrPortFrom(a, port).String()
}

func (n *natStack) forwardTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	addr := n.hostAddr(id.LocalAddress, id.LocalPort)
	name := fmt.Sprintf("%v:%d -> %s", id.RemoteAddress, id.RemotePort, addr)
	debugf("tcp forward %s", name)
	markStage(name, "dial")
	t0 := time.Now()
	host, err := net.DialTimeout("tcp4", addr, connectTimeout)
	if err != nil {
		debugf("tcp dial %s: %v", name, err)
		markStage(name, "")
		// Refused, unreachable or timed out: the guest's connect() fails
		// as it would against the destination itself.
		n.tcpRefused.Add(1)
		r.Complete(true)
		return
	}
	markStage(name, "handshake")
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		debugf("tcp endpoint %s: %v", name, terr)
		markStage(name, "")
		r.Complete(true)
		host.Close()
		return
	}
	r.Complete(false)
	markStage(name, "relay")
	debugf("tcp ready %s (dial %v)", name, time.Since(t0))
	n.tcpFlows.Add(1)
	relayTCP(name, gonet.NewTCPConn(&wq, ep), ep, host.(*net.TCPConn))
	markStage(name, "")
}

// Hide io.ReaderFrom / io.WriterTo so io.CopyBuffer uses our buffer.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

var relayBufs = sync.Pool{New: func() any { b := make([]byte, relayBuf); return &b }}

// relayTCP copies both ways until both are done. A clean EOF is passed on as
// a half-close; an error resets the other side, so a cut-off stream never
// looks complete.
func relayTCP(name string, guest *gonet.TCPConn, gep tcpip.Endpoint, host *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bp := relayBufs.Get().(*[]byte)
		defer relayBufs.Put(bp)
		n, err := io.CopyBuffer(writerOnly{guest}, readerOnly{host}, *bp)
		debugf("tcp %s: %d B to the guest, %v", name, n, err)
		if err != nil {
			gep.Abort()
		} else {
			guest.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		bp := relayBufs.Get().(*[]byte)
		defer relayBufs.Put(bp)
		n, err := io.CopyBuffer(writerOnly{host}, readerOnly{guest}, *bp)
		debugf("tcp %s: %d B to the host, %v", name, n, err)
		if err != nil {
			host.SetLinger(0)
			host.Close()
		} else {
			host.CloseWrite()
		}
	}()
	wg.Wait()
	guest.Close()
	host.Close()
}

func (n *natStack) forwardUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	var wq waiter.Queue
	ep, terr := r.CreateEndpoint(&wq)
	if terr != nil {
		return true
	}
	guest := gonet.NewUDPConn(&wq, ep)
	host, err := net.Dial("udp4", n.hostAddr(id.LocalAddress, id.LocalPort))
	if err != nil {
		guest.Close()
		return true
	}
	n.udpFlows.Add(1)
	go relayUDP(guest, host)
	return true
}

func relayUDP(guest *gonet.UDPConn, host net.Conn) {
	var once sync.Once
	stop := func() { once.Do(func() { guest.Close(); host.Close() }) }
	go func() {
		b := make([]byte, 65536)
		for {
			host.SetReadDeadline(time.Now().Add(udpIdle))
			k, err := host.Read(b)
			if err != nil {
				break
			}
			guest.Write(b[:k])
		}
		stop()
	}()
	b := make([]byte, 65536)
	for {
		guest.SetReadDeadline(time.Now().Add(udpIdle))
		k, err := guest.Read(b)
		if err != nil {
			break
		}
		host.Write(b[:k])
	}
	stop()
}

// dialGuest opens a TCP connection from the gateway to the guest, keeping
// its endpoint so a host-side failure can reset it.
func (n *natStack) dialGuest(ctx context.Context, guest tcpip.FullAddress) (*gonet.TCPConn, tcpip.Endpoint, error) {
	var wq waiter.Queue
	ep, terr := n.s.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, nil, errors.New(terr.String())
	}
	we, ch := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)
	if terr := ep.Bind(tcpip.FullAddress{NIC: nicID, Addr: n.gateway}); terr != nil {
		ep.Close()
		return nil, nil, errors.New(terr.String())
	}
	terr = ep.Connect(guest)
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ch:
			terr = ep.LastError()
		case <-ctx.Done():
			ep.Close()
			return nil, nil, ctx.Err()
		}
	}
	if terr != nil {
		ep.Close()
		return nil, nil, errors.New(terr.String())
	}
	return gonet.NewTCPConn(&wq, ep), ep, nil
}

func (n *natStack) serveForward(l net.Listener, guest tcpip.FullAddress) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
			defer cancel()
			g, gep, err := n.dialGuest(ctx, guest)
			if err != nil {
				c.(*net.TCPConn).SetLinger(0)
				c.Close()
				return
			}
			n.tcpFlows.Add(1)
			relayTCP(fmt.Sprintf("%v -> guest port %d", c.RemoteAddr(), guest.Port), g, gep, c.(*net.TCPConn))
		}()
	}
}

func cbytes(p *C.uint8_t, n int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(p)), n)
}

func setErr(buf *C.char, n C.int32_t, err error) {
	if buf == nil || n <= 0 {
		return
	}
	out := unsafe.Slice((*byte)(unsafe.Pointer(buf)), int(n))
	k := copy(out[:len(out)-1], err.Error())
	out[k] = 0
}

func lookup(h C.uintptr_t) *natStack {
	return cgo.Handle(h).Value().(*natStack)
}

// tvg_new starts a stack whose NIC has MAC mac (6 bytes) and owns gateway
// gw (4 bytes) on a /prefix network, with an Ethernet MTU of mtu. Frames for
// the guest go to send(ctx, ...) from any thread, until tvg_close returns.
// Returns 0 (and a message in errbuf) on failure.
//
//export tvg_new
func tvg_new(gw *C.uint8_t, prefix C.int32_t, mac *C.uint8_t, mtu C.int32_t,
	send C.tvg_send_fn, ctx unsafe.Pointer, errbuf *C.char, errlen C.int32_t) C.uintptr_t {
	var gw4 [4]byte
	copy(gw4[:], cbytes(gw, 4))
	ep := &linkEP{
		send: send,
		ctx:  ctx,
		mtu:  uint32(mtu) + header.EthernetMinimumSize,
		mac:  tcpip.LinkAddress(string(cbytes(mac, 6))),
		in:   make(chan *stack.PacketBuffer, inputQueue),
		done: make(chan struct{}),
	}
	ep.bufs.New = func() any { b := make([]byte, 0, 64*1024+128); return &b }
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4},
	})
	fail := func(what string, terr tcpip.Error) C.uintptr_t {
		setErr(errbuf, errlen, fmt.Errorf("%s: %s", what, terr))
		s.Close()
		return 0
	}
	sack := tcpip.TCPSACKEnabled(true)
	if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); terr != nil {
		return fail("SACK", terr)
	}
	// Up to 8 MiB windows, autotuned (as Linux's defaults allow 6 MiB).
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 1 << 20, Max: 8 << 20}
	if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); terr != nil {
		return fail("receive buffer", terr)
	}
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 1 << 20, Max: 8 << 20}
	if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); terr != nil {
		return fail("send buffer", terr)
	}
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); terr != nil {
		return fail("receive buffer moderation", terr)
	}
	// No TIME_WAIT. The stack closes first whenever the host does, and the
	// guest, the passive closer, holds none and may reuse its port at once.
	// A SYN for a 4-tuple in TIME_WAIT is passed only to a listening endpoint,
	// which a forwarder isn't, so the guest's new connection would stall until
	// TIME_WAIT ended (60 s). Over the virtual link nothing is reordered; a
	// FIN the guest retransmits afterwards draws a RST, which ends its
	// LAST_ACK just as well (as in tinyvmm's NAT).
	tw := tcpip.TCPTimeWaitTimeoutOption(0)
	if terr := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tw); terr != nil {
		return fail("TIME_WAIT timeout", terr)
	}
	if terr := s.CreateNIC(nicID, ethernet.New(ep)); terr != nil {
		return fail("NIC", terr)
	}
	gateway := tcpip.AddrFrom4(gw4)
	addr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: gateway, PrefixLen: int(prefix)},
	}
	if terr := s.AddProtocolAddress(nicID, addr, stack.AddressProperties{}); terr != nil {
		return fail("gateway address", terr)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	if terr := s.SetPromiscuousMode(nicID, true); terr != nil {
		return fail("promiscuous mode", terr)
	}
	if terr := s.SetSpoofing(nicID, true); terr != nil {
		return fail("spoofing", terr)
	}
	n := &natStack{s: s, ep: ep, gateway: gateway}
	tcpFwd := tcp.NewForwarder(s, 0, 1024, n.forwardTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, n.forwardUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	go ep.deliver()
	return C.uintptr_t(cgo.NewHandle(n))
}

// tvg_input queues a guest frame (copied; see linkEP.Capabilities for its
// checksums).
//
//export tvg_input
func tvg_input(h C.uintptr_t, frame *C.uint8_t, length C.int32_t) {
	n := lookup(h)
	if n.closed.Load() || length <= 0 {
		return
	}
	v := buffer.NewViewSize(int(length))
	copy(v.AsSlice(), cbytes(frame, int(length)))
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithView(v)})
	select {
	case n.ep.in <- pkt:
	default:
		n.inputDrops.Add(1)
		pkt.DecRef()
	}
}

// tvg_add_portfwd forwards host TCP hostIP:hostPort to the guest's
// guestIP:guestPort. Returns 0, or -1 with a message in errbuf.
//
//export tvg_add_portfwd
func tvg_add_portfwd(h C.uintptr_t, hostIP *C.uint8_t, hostPort C.int32_t,
	guestIP *C.uint8_t, guestPort C.int32_t, errbuf *C.char, errlen C.int32_t) C.int32_t {
	n := lookup(h)
	var hip, gip [4]byte
	copy(hip[:], cbytes(hostIP, 4))
	copy(gip[:], cbytes(guestIP, 4))
	l, err := net.Listen("tcp4", netip.AddrPortFrom(netip.AddrFrom4(hip), uint16(hostPort)).String())
	if err != nil {
		setErr(errbuf, errlen, err)
		return -1
	}
	n.mu.Lock()
	n.forwards = append(n.forwards, portForward{l: l})
	n.mu.Unlock()
	go n.serveForward(l, tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFrom4(gip), Port: uint16(guestPort)})
	return 0
}

// tvg_stats fills out[0..len) with counters: TCP segments sent, received,
// retransmitted, fast-retransmitted, RTOs, segments D-SACKed, guest frames
// dropped (input queue full), TCP flows relayed, guest connects refused,
// UDP flows.
//
//export tvg_stats
func tvg_stats(h C.uintptr_t, out *C.uint64_t, length C.int32_t) {
	n := lookup(h)
	t := n.s.Stats().TCP
	vals := []uint64{
		t.SegmentsSent.Value(),
		t.ValidSegmentsReceived.Value(),
		t.Retransmits.Value(),
		t.FastRetransmit.Value(),
		t.Timeouts.Value(),
		t.SegmentsAckedWithDSACK.Value(),
		n.inputDrops.Load(),
		n.tcpFlows.Load(),
		n.tcpRefused.Load(),
		n.udpFlows.Load(),
	}
	dst := unsafe.Slice((*uint64)(unsafe.Pointer(out)), int(length))
	copy(dst, vals)
}

// tvg_close stops the stack. No send callback runs once it returns.
//
//export tvg_close
func tvg_close(h C.uintptr_t) {
	n := lookup(h)
	n.closeOnce.Do(func() {
		n.closed.Store(true)
		if debugLevel >= 1 {
			dumpCounters("stack", reflect.ValueOf(n.s.Stats()))
			if nic, ok := n.s.NICInfo()[nicID]; ok {
				dumpCounters("nic", reflect.ValueOf(nic.Stats))
			}
			dumpStages()
		}
		n.mu.Lock()
		for _, f := range n.forwards {
			f.l.Close()
		}
		n.mu.Unlock()
		n.ep.mu.Lock()
		n.ep.closed = true
		n.ep.mu.Unlock()
		close(n.ep.done)
		n.s.Close()
		n.s.Wait()
	})
	cgo.Handle(h).Delete()
}

// tvg_version writes gVisor's module version (and the Go toolchain's) into
// buf.
//
//export tvg_version
func tvg_version(buf *C.char, length C.int32_t) {
	v, gov := "unknown", "unknown Go"
	if bi, ok := debug.ReadBuildInfo(); ok {
		gov = bi.GoVersion
		for _, d := range bi.Deps {
			if d.Path == "gvisor.dev/gvisor" {
				v = d.Version
			}
		}
	}
	setErr(buf, length, errors.New(v+", "+gov))
}
