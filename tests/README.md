# jwt_tool target range & tests

End-to-end coverage for the ECDSA zero-value signature attack (`-X z`).

## Layout

- `lab_server.py` — a minimal ES256 JWT target range (stdlib `http.server`
  plus `pycryptodomex`). It mints legitimate tokens at `GET /issue` and
  exposes two verifiers on `GET /verify`:
  - `mode=vulnerable` — skips ECDSA range checks, so a signature with
    `r=0, s=0` is accepted (the bypass).
  - `mode=patched` — rejects `r`/`s` outside `[1, n-1]` before verifying.
- `conftest.py` — pytest fixtures: an isolated `HOME` with a seeded
  `jwtconf.ini`, a spawned lab server, and a subprocess runner for
  `jwt_tool.py`.
- `test_zero_ec_sig.py` — offline token-generation/CLI tests, target-range
  detection tests (vulnerable vs patched), and a Playbook scan test.

## Run

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest tests/ -q
```

The lab can also be run manually:

```
.venv/bin/python tests/lab_server.py 8091
curl -s http://127.0.0.1:8091/issue
```
