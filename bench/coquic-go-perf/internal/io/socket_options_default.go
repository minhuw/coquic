//go:build !linux

package perfio

import "net"

func configureNoIPFragmentation(_ *net.UDPConn) error {
	return nil
}
