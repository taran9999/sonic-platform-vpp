#!/usr/bin/env python3
"""sonic-ext MACsec GCM-AES-128 SecY tests.

L2 xconnect pg0 <-> pg1.  Egress SecY on pg1 encrypts frames that
arrive on pg0; ingress SecY on pg0 decrypts frames injected there.
EAPOL (0x888E) and LACP (0x8809) must pass a protected port unmodified.
"""

import struct
import unittest

from asfframework import VppTestRunner
from framework import VppTestCase
from scapy.compat import raw
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

# IEEE 802.1AE-2018 Annex published GCM-AES-128 test SAK (not a secret).
TEST_SAK = bytes.fromhex("ad7a2bd03eac835a6f620fdcb506b345")
TEST_SCI = 0x12153524C0895E81
MACSEC_ETHERTYPE = 0x88E5
EAPOL_ETHERTYPE = 0x888E
LACP_ETHERTYPE = 0x8809
CS_GCM_AES_128 = 0
DIR_EGRESS = 0
DIR_INGRESS = 1


def _aes_gcm_encrypt(key, iv, aad, plaintext):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM(key).encrypt(iv, plaintext, aad)
    except ImportError:
        from Crypto.Cipher import AES

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext + tag


def _gcm_available():
    try:
        _aes_gcm_encrypt(TEST_SAK, b"\x00" * 12, b"a" * 28, b"hello")
        return True
    except Exception:
        return False


HAVE_GCM = _gcm_available()


def macsec_protect(frame, sak, sci, an=0, pn=1, send_sci=True):
    """Build a confidentiality (E=1,C=1) MACsec frame matching the plugin."""
    da, sa, rest = frame[:6], frame[6:12], frame[12:]
    tci = (0x20 if send_sci else 0) | 0x0C | (an & 3)
    sl = len(rest) if len(rest) < 48 else 0
    sectag = struct.pack("!BBBBI", 0x88, 0xE5, tci, sl, pn & 0xFFFFFFFF)
    if send_sci:
        sectag += struct.pack("!Q", sci)
    iv = struct.pack("!QI", sci, pn & 0xFFFFFFFF)
    aad = da + sa + sectag
    return da + sa + sectag + _aes_gcm_encrypt(sak, iv, aad, rest)


class SonicExtMacsecBase(VppTestCase):
    """sonic-ext MACsec test base"""

    extra_vpp_plugin_config = [
        "plugin",
        "linux_cp_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "sonic_ext_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "crypto_native_plugin.so",
        "{",
        "enable",
        "}",
        "plugin",
        "crypto_openssl_plugin.so",
        "{",
        "enable",
        "}",
    ]

    @classmethod
    def setUpClass(cls):
        super(SonicExtMacsecBase, cls).setUpClass()
        cls.create_pg_interfaces(range(2))

    def setUp(self):
        super(SonicExtMacsecBase, self).setUp()
        for interface in self.pg_interfaces:
            interface.admin_up()
        self.vapi.sw_interface_set_l2_xconnect(
            rx_sw_if_index=self.pg0.sw_if_index,
            tx_sw_if_index=self.pg1.sw_if_index,
            enable=True,
        )
        self.vapi.sw_interface_set_l2_xconnect(
            rx_sw_if_index=self.pg1.sw_if_index,
            tx_sw_if_index=self.pg0.sw_if_index,
            enable=True,
        )
        self._secy = []

    def tearDown(self):
        for args in reversed(self._secy):
            try:
                self.vapi.sonic_ext_macsec_port_add_del(**args, is_add=False)
            except Exception:
                pass
        self._secy = []
        super(SonicExtMacsecBase, self).tearDown()
        for interface in self.pg_interfaces:
            interface.admin_down()

    def sak32(self):
        return (TEST_SAK + bytes(32))[:32]

    def add_secy(self, sw_if_index, direction, send_sci=1, an=0):
        self.vapi.sonic_ext_macsec_port_add_del(
            sw_if_index=sw_if_index,
            direction=direction,
            encrypt=1,
            send_sci=send_sci,
            replay_protect=0,
            replay_window=0,
            is_add=True,
        )
        self._secy.append(dict(sw_if_index=sw_if_index, direction=direction,
                               encrypt=1, send_sci=send_sci, replay_protect=0,
                               replay_window=0))
        self.vapi.sonic_ext_macsec_sc_add_del(
            sw_if_index=sw_if_index,
            direction=direction,
            sci=TEST_SCI,
            cipher_suite=CS_GCM_AES_128,
            explicit_sci=send_sci,
            confidentiality_offset=0,
            is_add=True,
        )
        self.vapi.sonic_ext_macsec_sa_add_del(
            sw_if_index=sw_if_index,
            direction=direction,
            sci=TEST_SCI,
            an=an,
            sak=self.sak32(),
            sak_len=16,
            salt=bytes(12),
            ssci=0,
            xpn_en=0,
            init_xpn=1,
            is_add=True,
        )
        self.vapi.sonic_ext_macsec_sc_set_encoding_an(
            sw_if_index=sw_if_index, sci=TEST_SCI, an=an
        )

    def data_pkt(self):
        return (
            Ether(dst=self.pg1.local_mac, src=self.pg0.remote_mac)
            / IP(src="10.0.0.1", dst="10.0.0.2", ttl=64)
            / UDP(sport=1234, dport=4321)
            / Raw(b"macsec-payload")
        )

    def ctrl_pkt(self, etype):
        dst = "01:80:c2:00:00:03" if etype == EAPOL_ETHERTYPE else "01:80:c2:00:00:02"
        return Ether(dst=dst, src=self.pg0.remote_mac, type=etype) / Raw(
            b"\x01\x01" + b"\x00" * 40
        )

    def wire_pkt(self, frame):
        """Rebuild a captured/constructed frame without scapy trying to parse 0x88E5."""
        return Ether(dst=frame[:6], src=frame[6:12], type=int.from_bytes(frame[12:14], "big")) / Raw(
            frame[14:]
        )


class TestSonicExtMacsec(SonicExtMacsecBase):
    """sonic-ext MACsec GCM-AES-128"""

    def test_feature_default_enabled(self):
        """macsec is a SAIVPP-owned feature, on by default"""
        self.assertTrue(self.vapi.sonic_ext_feature_get(feature="macsec").enabled)

    @unittest.skipUnless(HAVE_GCM, "no AES-GCM library for the IEEE known-answer vector")
    def test_encrypt_known_answer(self):
        """plaintext on pg0 is GCM-AES-128 encapsulated on pg1"""
        self.add_secy(self.pg1.sw_if_index, DIR_EGRESS)
        pkt = self.data_pkt()
        expected = macsec_protect(raw(pkt), TEST_SAK, TEST_SCI, an=0, pn=1, send_sci=True)
        rx = self.send_and_expect(self.pg0, [pkt], self.pg1)[0]
        got = raw(rx)
        self.assertEqual(int.from_bytes(got[12:14], "big"), MACSEC_ETHERTYPE)
        self.assertEqual(got[: len(expected)], expected)

    @unittest.skipUnless(HAVE_GCM, "no AES-GCM library to build the decrypt input")
    def test_decrypt_round_trip(self):
        """ciphertext on pg0 decrypts to the original Ethernet frame on pg1"""
        pkt = self.data_pkt()
        protected = macsec_protect(raw(pkt), TEST_SAK, TEST_SCI, an=0, pn=1, send_sci=True)
        self.add_secy(self.pg0.sw_if_index, DIR_INGRESS)
        rx = self.send_and_expect(self.pg0, [self.wire_pkt(protected)], self.pg1)[0]
        self.assertEqual(raw(rx)[: len(raw(pkt))], raw(pkt))

    @unittest.skipUnless(HAVE_GCM, "no AES-GCM library to build a corrupted ICV frame")
    def test_bad_icv_dropped(self):
        """corrupted ICV is dropped and in-pkts-not-valid increments"""
        pkt = self.data_pkt()
        protected = bytearray(
            macsec_protect(raw(pkt), TEST_SAK, TEST_SCI, an=0, pn=1, send_sci=True)
        )
        protected[-1] ^= 0xFF
        self.add_secy(self.pg0.sw_if_index, DIR_INGRESS)
        before = self.statistics.get_err_counter(
            "/err/sonic-ext-macsec-decrypt/dropped: ICV check failed"
        )
        self.send_and_assert_no_replies(self.pg0, [self.wire_pkt(bytes(protected))])
        self.assertEqual(
            self.statistics.get_err_counter(
                "/err/sonic-ext-macsec-decrypt/dropped: ICV check failed"
            ),
            before + 1,
        )
        sa_out = self.vapi.cli("show macsec sa")
        self.assertRegex(sa_out, r"in-not-valid 1")

    def test_eapol_lacp_bypass(self):
        """EAPOL and LACP on a protected port are unmodified"""
        self.add_secy(self.pg1.sw_if_index, DIR_EGRESS)
        self.add_secy(self.pg0.sw_if_index, DIR_INGRESS)
        for etype in (EAPOL_ETHERTYPE, LACP_ETHERTYPE):
            pkt = self.ctrl_pkt(etype)
            rx = self.send_and_expect(self.pg0, [pkt], self.pg1)[0]
            self.assertEqual(raw(rx)[: len(raw(pkt))], raw(pkt))
            self.assertEqual(int.from_bytes(raw(rx)[12:14], "big"), etype)

    def test_show_macsec_hides_sak(self):
        """show macsec sa prints key length, never the SAK"""
        self.add_secy(self.pg1.sw_if_index, DIR_EGRESS)
        out = self.vapi.cli("show macsec sa")
        self.assertIn("sak-len 16", out)
        self.assertIn("gcm-aes-128", out)
        self.assertNotIn(TEST_SAK.hex(), out.lower())
        self.assertNotIn(TEST_SAK.hex().upper(), out)
        self.assertRegex(self.vapi.cli("show macsec"), r"macsec:\s+on")

    def test_phase1_rejects_xpn_and_aes256(self):
        """Phase 1 rejects AES-256, XPN, and sak_len != 16"""
        self.vapi.sonic_ext_macsec_port_add_del(
            sw_if_index=self.pg1.sw_if_index,
            direction=DIR_EGRESS,
            encrypt=1,
            send_sci=1,
            replay_protect=0,
            replay_window=0,
            is_add=True,
        )
        self._secy.append(
            dict(
                sw_if_index=self.pg1.sw_if_index,
                direction=DIR_EGRESS,
                encrypt=1,
                send_sci=1,
                replay_protect=0,
                replay_window=0,
            )
        )
        with self.vapi.assert_negative_api_retval():
            self.vapi.sonic_ext_macsec_sc_add_del(
                sw_if_index=self.pg1.sw_if_index,
                direction=DIR_EGRESS,
                sci=TEST_SCI,
                cipher_suite=1,
                explicit_sci=1,
                confidentiality_offset=0,
                is_add=True,
            )
        self.vapi.sonic_ext_macsec_sc_add_del(
            sw_if_index=self.pg1.sw_if_index,
            direction=DIR_EGRESS,
            sci=TEST_SCI,
            cipher_suite=CS_GCM_AES_128,
            explicit_sci=1,
            confidentiality_offset=0,
            is_add=True,
        )
        with self.vapi.assert_negative_api_retval():
            self.vapi.sonic_ext_macsec_sa_add_del(
                sw_if_index=self.pg1.sw_if_index,
                direction=DIR_EGRESS,
                sci=TEST_SCI,
                an=0,
                sak=self.sak32(),
                sak_len=32,
                salt=bytes(12),
                ssci=0,
                xpn_en=0,
                init_xpn=1,
                is_add=True,
            )
        with self.vapi.assert_negative_api_retval():
            self.vapi.sonic_ext_macsec_sa_add_del(
                sw_if_index=self.pg1.sw_if_index,
                direction=DIR_EGRESS,
                sci=TEST_SCI,
                an=0,
                sak=self.sak32(),
                sak_len=16,
                salt=bytes(12),
                ssci=0,
                xpn_en=1,
                init_xpn=1,
                is_add=True,
            )


if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
