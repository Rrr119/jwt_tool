#!/usr/bin/env python3
"""
Minimal JWT target range used to exercise jwt_tool's ECDSA zero-value
signature attack (-X z).

The same ES256 key pair backs two endpoints:
  GET /issue                          -> mint a legitimate ES256 token
  GET /verify?mode=vulnerable         -> verifier that skips ECDSA range
                                         checks (accepts r=0, s=0)
  GET /verify?mode=patched            -> verifier that rejects r/s values
                                         outside [1, n-1] before verifying

The "vulnerable" branch deliberately models implementations/libraries that
feed attacker-controlled signature integers straight into the ECDSA equation
without first validating 1 <= r, s <= n-1.
"""
import base64
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().strip("=")


def b64u_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


KEY_PATH = os.environ.get("LAB_EC_KEY", os.path.join(os.path.dirname(__file__), "lab_ec_key.pem"))


def load_or_create_key():
    if os.path.exists(KEY_PATH):
        return ECC.import_key(open(KEY_PATH).read())
    key = ECC.generate(curve="P-256")
    with open(KEY_PATH, "w") as keyfile:
        keyfile.write(key.export_key(format="PEM"))
    return key


KEY = load_or_create_key()


def issue_token():
    header = {"typ": "JWT", "alg": "ES256"}
    payload = {"user": "guest", "role": "user"}
    signing_input = b64u(json.dumps(header, separators=(",", ":")).encode()) + "." + \
                    b64u(json.dumps(payload, separators=(",", ":")).encode())
    signer = DSS.new(KEY, "fips-186-3", encoding="der")
    signature = signer.sign(SHA256.new(signing_input.encode()))
    return signing_input + "." + b64u(signature)


def decode_der_ints(signature):
    # Parse the two INTEGERs (r, s) out of a DER ECDSA-Sig-Value.
    if signature[0] != 0x30:
        raise ValueError("not a DER sequence")
    offset = 2
    ints = []
    for _ in range(2):
        if signature[offset] != 0x02:
            raise ValueError("expected DER INTEGER")
        length = signature[offset + 1]
        value = int.from_bytes(signature[offset + 2:offset + 2 + length], "big")
        ints.append(value)
        offset += 2 + length
    return ints[0], ints[1]


def verify_token(token, mode):
    try:
        head_b64, payload_b64, sig_b64 = token.split(".")
        header = json.loads(b64u_decode(head_b64))
        if header.get("alg") != "ES256":
            return 400, {"status": "error", "reason": "unsupported alg"}
        signature = b64u_decode(sig_b64)
        r_value, s_value = decode_der_ints(signature)
        order = int(KEY._curve.order)
        if mode == "patched":
            if not (1 <= r_value < order and 1 <= s_value < order):
                return 401, {"status": "rejected", "reason": "signature integer out of range"}
        elif mode == "vulnerable":
            # The bug: zero (or otherwise out-of-range) integers are trusted
            # and short-circuit the verification instead of being rejected.
            if r_value == 0 and s_value == 0:
                return 200, {"status": "accepted", "reason": "zero-value signature bypass",
                             "claims": json.loads(b64u_decode(payload_b64))}
        else:
            return 400, {"status": "error", "reason": "unknown mode"}
        verifier = DSS.new(KEY.public_key(), "fips-186-3", encoding="der")
        verifier.verify(SHA256.new((head_b64 + "." + payload_b64).encode()), signature)
        return 200, {"status": "accepted", "reason": "valid signature",
                     "claims": json.loads(b64u_decode(payload_b64))}
    except ValueError as error:
        return 401, {"status": "rejected", "reason": str(error)}
    except Exception:
        return 401, {"status": "rejected", "reason": "invalid token"}


class LabHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _respond(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/issue":
            self._respond(200, {"token": issue_token()})
            return
        if parsed.path == "/verify":
            mode = parse_qs(parsed.query).get("mode", ["vulnerable"])[0]
            token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if not token:
                self._respond(400, {"status": "error", "reason": "missing bearer token"})
                return
            code, body = verify_token(token, mode)
            self._respond(code, body)
            return
        self._respond(404, {"status": "error", "reason": "not found"})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
    server = HTTPServer(("127.0.0.1", port), LabHandler)
    print(f"JWT lab listening on http://127.0.0.1:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
