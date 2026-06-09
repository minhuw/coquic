package perfio

import (
	"fmt"
	"net"
	"strconv"
	"time"

	coquic "github.com/minhuw/coquic/bindings/go/coquic"
)

const (
	MaxUDPDatagramSize       = 64 * 1024
	MaxBufferedSendDatagrams = 4096
)

type Route struct {
	Peer                      *net.UDPAddr
	AddressValidationIdentity []byte
}

type TxDatagram struct {
	RouteHandle coquic.RouteHandle
	Bytes       []byte
	Ecn         coquic.EcnCodepoint
	IsPMTUProbe bool
}

type RxDatagram struct {
	Bytes                     []byte
	RouteHandle               coquic.RouteHandle
	AddressValidationIdentity []byte
}

type UdpRuntime struct {
	socket          *net.UDPConn
	start           time.Time
	routesByHandle  map[coquic.RouteHandle]Route
	handlesByPeer   map[string]coquic.RouteHandle
	nextRouteHandle coquic.RouteHandle
	sendBuffer      []TxDatagram
	recvBufferSize  int
}

type WaitKind int

const (
	WaitDatagram WaitKind = iota
	WaitTimer
	WaitIdle
)

type WaitEvent struct {
	Kind     WaitKind
	Datagram RxDatagram
}

func NewClient(host string, port uint16, recvBufferSize uint64) (*UdpRuntime, coquic.RouteHandle, []byte, error) {
	peer, err := resolveRemote(host, port)
	if err != nil {
		return nil, 0, nil, err
	}
	bindAddr := &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	if peer.IP.To4() == nil {
		bindAddr = &net.UDPAddr{IP: net.IPv6zero, Port: 0}
	}
	socket, err := net.ListenUDP("udp", bindAddr)
	if err != nil {
		return nil, 0, nil, err
	}
	if err := configureNoIPFragmentation(socket); err != nil {
		socket.Close()
		return nil, 0, nil, err
	}
	runtime := newRuntime(socket, recvBufferSize)
	route := runtime.EnsureRoute(peer)
	identity := runtime.AddressValidationIdentity(route)
	if identity == nil {
		socket.Close()
		return nil, 0, nil, fmt.Errorf("missing client primary route identity")
	}
	return runtime, route, append([]byte(nil), identity...), nil
}

func NewServer(host string, port uint16, recvBufferSize uint64) (*UdpRuntime, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	socket, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}
	if err := configureNoIPFragmentation(socket); err != nil {
		socket.Close()
		return nil, err
	}
	return newRuntime(socket, recvBufferSize), nil
}

func (r *UdpRuntime) Close() error {
	if r == nil || r.socket == nil {
		return nil
	}
	return r.socket.Close()
}

func (r *UdpRuntime) NowUs() coquic.TimeUs {
	return coquic.TimeUs(time.Since(r.start).Microseconds())
}

func (r *UdpRuntime) EnsureRoute(peer *net.UDPAddr) coquic.RouteHandle {
	key := peer.String()
	if handle, ok := r.handlesByPeer[key]; ok {
		return handle
	}
	handle := r.nextRouteHandle
	r.nextRouteHandle++
	r.handlesByPeer[key] = handle
	r.routesByHandle[handle] = Route{
		Peer:                      peer,
		AddressValidationIdentity: addressValidationIdentity(peer),
	}
	return handle
}

func (r *UdpRuntime) InboundDatagram(rx RxDatagram) coquic.InboundDatagram {
	return coquic.InboundDatagram{
		Bytes:                     rx.Bytes,
		RouteHandle:               rx.RouteHandle,
		HasRouteHandle:            true,
		AddressValidationIdentity: rx.AddressValidationIdentity,
		Ecn:                       coquic.EcnUnavailable,
	}
}

func (r *UdpRuntime) CollectResultEffects(result *coquic.QueryResult) ([]coquic.Effect, error) {
	out := make([]coquic.Effect, 0)
	err := result.ForEachEffect(func(effect coquic.Effect) error {
		switch effect.Kind {
		case coquic.EffectSendDatagram:
			if len(r.sendBuffer) >= MaxBufferedSendDatagrams {
				return fmt.Errorf("send buffer exceeded before flush; call flush_sends more often")
			}
			if !effect.HasRouteHandle {
				return fmt.Errorf("send datagram missing route handle")
			}
			r.sendBuffer = append(r.sendBuffer, TxDatagram{
				RouteHandle: effect.RouteHandle,
				Bytes:       effect.Bytes,
				Ecn:         effect.Ecn,
				IsPMTUProbe: effect.IsPMTUProbe,
			})
		case coquic.EffectReceiveStreamData,
			coquic.EffectStateEvent,
			coquic.EffectConnectionLifecycleEvent,
			coquic.EffectPeerResetStream,
			coquic.EffectPeerStopSending:
			out = append(out, effect)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (r *UdpRuntime) FlushSends() error {
	datagrams := r.sendBuffer
	r.sendBuffer = nil
	for _, datagram := range datagrams {
		route, ok := r.routesByHandle[datagram.RouteHandle]
		if !ok {
			return fmt.Errorf("unknown route handle %d", datagram.RouteHandle)
		}
		_, err := r.socket.WriteToUDP(datagram.Bytes, route.Peer)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *UdpRuntime) SendBufferEmpty() bool {
	return len(r.sendBuffer) == 0
}

func (r *UdpRuntime) Recv() (RxDatagram, error) {
	buffer := make([]byte, r.recvBufferSize)
	length, peer, err := r.socket.ReadFromUDP(buffer)
	if err != nil {
		return RxDatagram{}, err
	}
	buffer = buffer[:length]
	route := r.EnsureRoute(peer)
	identity := r.AddressValidationIdentity(route)
	if identity == nil {
		identity = nil
	}
	return RxDatagram{
		Bytes:                     buffer,
		RouteHandle:               route,
		AddressValidationIdentity: append([]byte(nil), identity...),
	}, nil
}

func (r *UdpRuntime) Wait(nextWakeup coquic.TimeUs, hasNextWakeup bool, idleTimeout time.Duration) (WaitEvent, error) {
	if hasNextWakeup {
		now := r.NowUs()
		if nextWakeup <= now {
			return WaitEvent{Kind: WaitTimer}, nil
		}
		return r.waitWithTimeout(
			time.Duration(uint64(nextWakeup-now))*time.Microsecond,
			WaitTimer,
		)
	}

	return r.waitWithTimeout(idleTimeout, WaitIdle)
}

func (r *UdpRuntime) waitWithTimeout(timeout time.Duration, deadlineKind WaitKind) (WaitEvent, error) {
	if err := r.socket.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return WaitEvent{}, err
	}
	datagram, err := r.Recv()
	if deadlineErr(err) {
		return WaitEvent{Kind: deadlineKind}, nil
	}
	if err != nil {
		return WaitEvent{}, err
	}
	return WaitEvent{Kind: WaitDatagram, Datagram: datagram}, nil
}

func (r *UdpRuntime) AddressValidationIdentity(routeHandle coquic.RouteHandle) []byte {
	route, ok := r.routesByHandle[routeHandle]
	if !ok {
		return nil
	}
	return route.AddressValidationIdentity
}

func newRuntime(socket *net.UDPConn, recvBufferSize uint64) *UdpRuntime {
	return &UdpRuntime{
		socket:          socket,
		start:           time.Now(),
		routesByHandle:  make(map[coquic.RouteHandle]Route),
		handlesByPeer:   make(map[string]coquic.RouteHandle),
		nextRouteHandle: 1,
		recvBufferSize:  boundedDatagramBufferSize(recvBufferSize),
	}
}

func boundedDatagramBufferSize(size uint64) int {
	if size == 0 || size > MaxUDPDatagramSize {
		return MaxUDPDatagramSize
	}
	return int(size)
}

func resolveRemote(host string, port uint16) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, err
	}
	if addr == nil {
		return nil, fmt.Errorf("failed to resolve remote address")
	}
	return addr, nil
}

func addressValidationIdentity(peer *net.UDPAddr) []byte {
	if ipv4 := peer.IP.To4(); ipv4 != nil {
		identity := make([]byte, 0, 1+4+2)
		identity = append(identity, 0x04)
		identity = append(identity, ipv4...)
		identity = append(identity, byte(peer.Port>>8), byte(peer.Port))
		return identity
	}
	ipv6 := peer.IP.To16()
	identity := make([]byte, 0, 1+16+2)
	identity = append(identity, 0x06)
	identity = append(identity, ipv6...)
	identity = append(identity, byte(peer.Port>>8), byte(peer.Port))
	return identity
}

func deadlineErr(err error) bool {
	if err == nil {
		return false
	}
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
