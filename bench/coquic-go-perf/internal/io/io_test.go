package perfio

import (
	"net"
	"testing"
	"time"
)

func newLoopbackRuntime(t *testing.T) *UdpRuntime {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = socket.Close()
	})
	return newRuntime(socket, MaxUDPDatagramSize)
}

func TestWaitReportsTimerForFutureWakeupPastIdleTimeout(t *testing.T) {
	runtime := newLoopbackRuntime(t)
	event, err := runtime.Wait(runtime.NowUs()+2000, true, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != WaitTimer {
		t.Fatalf("expected WaitTimer, got %v", event.Kind)
	}
}

func TestWaitReportsIdleWhenNoWakeupIsScheduled(t *testing.T) {
	runtime := newLoopbackRuntime(t)
	event, err := runtime.Wait(0, false, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if event.Kind != WaitIdle {
		t.Fatalf("expected WaitIdle, got %v", event.Kind)
	}
}
