"""Caller identities: peer credentials (tracekit/identity/uid.py) and dev tokens (tracekit/identity/token.py)."""
import dataclasses
import os
import socket
import struct
import unittest
from unittest import mock

from tracekit import peercred
from tracekit.identity import token
from tracekit.identity.base import CallerIdentity
from tracekit.identity.uid import UidAuthenticator
from tracekit.signer.rpc_schema import RPCError


class Identity(unittest.TestCase):
    def test_frozen(self):
        i = CallerIdentity("uid", "501", True, {"pid": 1})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            i.subject = "0"
        self.assertEqual(hash(i), hash(CallerIdentity("uid", "501", True)))


class PeerUid(unittest.TestCase):
    def test_linux_uid_above_2_31_stays_unsigned(self):
        for uid in (2 ** 31 + 5, 2 ** 32 - 2):
            self.assertEqual(peercred.parse_ucred(struct.pack("iII", 42, uid, 7)), (42, uid))

    @unittest.skipUnless(hasattr(socket, "AF_UNIX") and peercred.has_peer_credentials(), "no Unix peer credentials")
    def test_real_socket_reports_own_uid(self):
        a, b = socket.socketpair(socket.AF_UNIX)
        with a, b:
            ident = UidAuthenticator().authenticate(a, {})
        self.assertEqual((ident.scheme, ident.subject, ident.attested), ("uid", str(os.getuid()), True))

    def test_no_credentials_is_unauthenticated(self):
        with mock.patch.object(peercred, "peer", return_value=(None, None)):
            with self.assertRaises(RPCError) as cm:
                UidAuthenticator().authenticate(object(), {})
        self.assertEqual(cm.exception.code, "unauthenticated")


class DevToken(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.tok = token.DevToken("dev", {"status", "decide"}, ttl_s=60, clock=lambda: self.now)

    def test_in_scope_and_unexpired(self):
        ident = self.tok.authenticate(None, {"method": "decide"})
        self.assertEqual((ident.scheme, ident.subject), ("token", "dev"))

    def test_out_of_scope_is_forbidden(self):
        with self.assertRaises(RPCError) as cm:
            self.tok.authenticate(None, {"method": "approval_decide"})
        self.assertEqual(cm.exception.code, "forbidden")

    def test_expired_is_unauthenticated(self):
        self.now += 60
        with self.assertRaises(RPCError) as cm:
            self.tok.authenticate(None, {"method": "status"})
        self.assertEqual(cm.exception.code, "unauthenticated")

    def test_proof_compared_in_constant_time(self):
        good = token.proof(self.tok.secret, "client", "n" * 16)
        with mock.patch.object(token.hmac, "compare_digest", wraps=token.hmac.compare_digest) as cd:
            token.check_proof(self.tok.secret, good, "client", "n" * 16)
            for bad in (token.proof(self.tok.secret, "signer", "n" * 16), token.proof("other", "client", "n" * 16), None):
                with self.assertRaises(RPCError) as cm:
                    token.check_proof(self.tok.secret, bad, "client", "n" * 16)
                self.assertEqual(cm.exception.code, "unauthenticated")
        self.assertEqual(cd.call_count, 4)
