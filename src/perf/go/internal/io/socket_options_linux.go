//go:build linux

package perfio

import (
	"errors"
	"net"
	"syscall"
)

const (
	ipMtuDiscover   = 10
	ipPmtudiscProbe = 3
	ipv6MtuDiscover = 23
)

func configureNoIPFragmentation(socket *net.UDPConn) error {
	raw, err := socket.SyscallConn()
	if err != nil {
		return err
	}

	var socketErr error
	controlErr := raw.Control(func(fd uintptr) {
		if err := setMtuDiscover(fd, syscall.IPPROTO_IP, ipMtuDiscover, ipPmtudiscProbe); err != nil {
			socketErr = err
			return
		}
		if err := setMtuDiscover(fd, syscall.IPPROTO_IPV6, ipv6MtuDiscover, ipPmtudiscProbe); err != nil {
			socketErr = err
		}
	})
	if controlErr != nil {
		return controlErr
	}
	return socketErr
}

func setMtuDiscover(fd uintptr, level int, name int, value int) error {
	err := syscall.SetsockoptInt(int(fd), level, name, value)
	if err == nil || errors.Is(err, syscall.ENOPROTOOPT) || errors.Is(err, syscall.EINVAL) {
		return nil
	}
	return err
}
