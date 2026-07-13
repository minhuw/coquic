import unittest

from coquic import EcnPolicy, TransportConfig
from coquic import _ffi as ffi


class EcnPolicyTest(unittest.TestCase):
    def test_default_and_alternate_policy_round_trip(self) -> None:
        self.assertEqual(ffi.FFI_ABI_VERSION, 11)

        raw = ffi.coquic_transport_config_t()
        raw.ecn_policy = ffi.COQUIC_ECN_POLICY_RFC8311_ECT1
        config = TransportConfig.from_raw(raw)

        self.assertEqual(config.ecn_policy, EcnPolicy.RFC8311_ECT1)
        encoded = config.to_raw()
        self.assertEqual(encoded.ecn_policy, ffi.COQUIC_ECN_POLICY_RFC8311_ECT1)

    def test_default_policy_is_rfc9000_ect0(self) -> None:
        config = TransportConfig.from_raw(ffi.coquic_transport_config_t())
        self.assertEqual(config.ecn_policy, EcnPolicy.RFC9000_ECT0)


if __name__ == "__main__":
    unittest.main()
