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
from tracekit.identity import uid
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
        for u in (2 ** 31 + 5, 2 ** 32 - 2):
            self.assertEqual(peercred.parse_ucred(struct.pack("iII", 42, u, 7)), (42, u))

    @unittest.skipUnless(hasattr(socket, "AF_UNIX") and peercred.has_peer_credentials(), "no Unix peer credentials")
    def test_real_socket_reports_own_uid(self):
        a, b = socket.socketpair(socket.AF_UNIX)
        with a, b:
            ident = UidAuthenticator(a).authenticate(a, {})
        self.assertEqual((ident.scheme, ident.subject, ident.attested), ("uid", str(os.getuid()), True))

    def test_no_credentials_is_unauthenticated(self):
        with mock.patch.object(peercred, "peer", return_value=(None, None)):
            with self.assertRaises(RPCError) as cm:
                UidAuthenticator(object())
        self.assertEqual(cm.exception.code, "unauthenticated")


@unittest.skipUnless(uid.PER_FRAME, "SO_PASSCRED / SCM_CREDENTIALS are Linux-only; macOS identity is fixed at connect")
class FrameCredentials(unittest.TestCase):
    def pair(self, passcred=True):
        a, b = socket.socketpair(socket.AF_UNIX)
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        if passcred:
            a.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        return a, b

    def refused(self, reader):
        with self.assertRaises(RPCError) as cm:
            reader.readline(100)
        self.assertEqual(cm.exception.code, "unauthenticated")

    def test_frames_from_the_connecting_uid_are_read(self):
        a, b = self.pair()
        b.sendall(b'{"n":1}\n{"n":2}\n{"n"')
        b.shutdown(socket.SHUT_WR)
        r = uid.CredentialReader(a, os.getuid())
        self.assertEqual([r.readline(100) for _ in range(4)], [b'{"n":1}\n', b'{"n":2}\n', b'{"n"', b""])
        self.assertEqual(r.readline(4), b"")

    def test_line_limit(self):
        a, b = self.pair()
        b.sendall(b"x" * 10 + b"\n")
        self.assertEqual(uid.CredentialReader(a, os.getuid()).readline(5), b"xxxxx")

    def test_frame_from_another_uid_is_refused(self):
        a, b = self.pair()
        b.sendall(b'{"n":1}\n')
        self.refused(uid.CredentialReader(a, os.getuid() + 1))

    def test_frame_without_credentials_is_refused(self):
        a, b = self.pair(passcred=False)
        b.sendall(b'{"n":1}\n')
        self.refused(uid.CredentialReader(a, os.getuid()))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "only a privileged sender may stamp another uid")
    def test_sender_stamping_another_uid_is_refused(self):
        a, b = self.pair()
        b.sendmsg([b'{"n":1}\n'], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack("iII", os.getpid(), 65534, 65534))])
        self.refused(uid.CredentialReader(a, 0))


class DevToken(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.tok = token.DevToken("dev", {"status", "decide"}, ttl_s=60, clock=lambda: self.now)

    def test_in_scope_and_unexpired(self):
        ident = self.tok.authenticate(None, {"method": "decide"})
        self.assertEqual((ident.scheme, ident.subject), ("token", "dev"))

    def test_out_of_scope_is_forbidden(self):
        for method in ("approval_decide", [], None):
            with self.assertRaises(RPCError) as cm:
                self.tok.authenticate(None, {"method": method})
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
