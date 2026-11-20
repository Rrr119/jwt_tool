import configparser
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
JWT_TOOL = REPO_ROOT / "jwt_tool.py"


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _seed_config(home_dir):
    """Write a valid jwtconf.ini so jwt_tool's first-run createConfig() is skipped."""
    config = configparser.ConfigParser(allow_no_value=True)
    config.optionxform = str
    config["crypto"] = {
        "pubkey": str(home_dir / "jwttool_custom_public_RSA.pem"),
        "privkey": str(home_dir / "jwttool_custom_private_RSA.pem"),
        "ecpubkey": str(home_dir / "jwttool_custom_public_EC.pem"),
        "ecprivkey": str(home_dir / "jwttool_custom_private_EC.pem"),
        "jwks": str(home_dir / "jwttool_custom_jwks.json"),
    }
    config["customising"] = {
        "useragent": "Mozilla/5.0 jwt_tool test",
        "jwks_kid": "jwt_tool",
    }
    config["services"] = {
        "jwt_tool_version": "2.3.0",
        "proxy": "False",
        "redir": "True",
        "jwksloc": "",
        "jwksdynamic": "",
        "httplistener": "",
    }
    config["input"] = {
        "wordlist": str(REPO_ROOT / "jwt-common.txt"),
        "commonHeaders": str(REPO_ROOT / "common-headers.txt"),
        "commonPayloads": str(REPO_ROOT / "common-payloads.txt"),
    }
    config["argvals"] = {
        "sigType": "",
        "targetUrl": "",
        "rate": "999999999",
        "cookies": "",
        "key": "",
        "keyList": "",
        "keyFile": "",
        "headerLoc": "",
        "payloadclaim": "",
        "headerclaim": "",
        "payloadvalue": "",
        "headervalue": "",
        "canaryvalue": "",
        "header": "",
        "exploitType": "",
        "scanMode": "",
        "reqMode": "",
        "postData": "",
        "resCode": "",
        "resSize": "",
        "resContent": "",
    }
    with open(home_dir / "jwtconf.ini", "w") as configfile:
        config.write(configfile)


@pytest.fixture()
def jwt_home(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    config_dir = home_dir / ".jwt_tool"
    config_dir.mkdir(parents=True)
    _seed_config(config_dir)
    monkeypatch.setenv("HOME", str(home_dir))
    (config_dir / "null.txt").touch()
    return home_dir


@pytest.fixture()
def lab_server():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, str(REPO_ROOT / "tests" / "lab_server.py"), str(port)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    base_url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    import urllib.request
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(base_url + "/issue", timeout=1) as response:
                if response.status == 200:
                    break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError("lab server failed to start")
    yield base_url
    proc.terminate()
    proc.wait(timeout=5)


def run_jwt_tool(*cli_args, env_home=None):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    result = subprocess.run(
        [sys.executable, str(JWT_TOOL), *cli_args],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return result
