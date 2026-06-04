package coquic

import "testing"

func TestConnectProducesInitialDatagram(t *testing.T) {
	config := DefaultEndpointConfig()
	config.Role = RoleClient
	config.ApplicationProtocol = []byte("coquic-perf/1")
	config.MaxOutboundDatagramSize = 60 * 1024

	endpoint, err := NewEndpoint(config)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Destroy()

	clientConfig := NewClientConfig(
		[]byte{0xc1, 0, 0, 0, 0, 0, 0, 1},
		[]byte{0x83, 0, 0, 0, 0, 0, 0, 0x41},
	)
	clientConfig.InitialRouteHandle = 7
	clientConfig.AddressValidationIdentity = []byte{0x04, 127, 0, 0, 1, 0x11, 0x51}

	handle, result, err := endpoint.Connect(clientConfig, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Destroy()
	if handle == 0 {
		t.Fatal("connect returned zero connection handle")
	}

	effects, err := result.Effects()
	if err != nil {
		t.Fatal(err)
	}
	for _, effect := range effects {
		if effect.Kind == EffectSendDatagram {
			if !effect.HasRouteHandle || effect.RouteHandle != 7 {
				t.Fatalf("send datagram route = %v/%d", effect.HasRouteHandle, effect.RouteHandle)
			}
			if len(effect.Bytes) == 0 {
				t.Fatal("send datagram has empty payload")
			}
			return
		}
	}
	t.Fatalf("connect result had no send datagram effect: %#v", effects)
}
