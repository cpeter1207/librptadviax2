#!/usr/bin/env python3
"""Independent loopback provider acceptance using the actual C header/DSO.

The quality image supplies a test-only Asterisk; installed IAX media is PBX-free.
"""

import json
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="iax-provider-") as temporary:
        root = Path(temporary)
        module = next(Path("/usr/lib").glob("*/asterisk/modules/chan_iax2.so")).parent
        (root / "asterisk.conf").write_text(
            "[directories]\n"
            + "".join(
                f"{key} => {root}\n"
                for key in (
                    "astetcdir",
                    "astvarlibdir",
                    "astdbdir",
                    "astkeydir",
                    "astagidir",
                    "astspooldir",
                    "astrundir",
                    "astlogdir",
                    "astcachedir",
                )
            )
            + f"astmoddir => {module}\nastdatadir => /usr/share/asterisk\n[options]\nverbose=0\ndebug=0\n"
        )
        (root / "modules.conf").write_text(
            "[modules]\nautoload=no\nload=chan_iax2.so\nload=pbx_config.so\nload=codec_ulaw.so\nload=app_echo.so\n"
        )
        (root / "logger.conf").write_text(
            "[logfiles]\nconsole => notice,warning,error,debug,verbose\n"
        )
        (root / "extensions.conf").write_text(
            "[phone-test]\nexten => 999,1,Answer()\nsame => n,Echo()\nsame => n,Hangup()\n"
        )
        (root / "iax.conf").write_text(
            f"[general]\nbindport={port}\nbindaddr=127.0.0.1\ndisallow=all\nallow=ulaw\nrequirecalltoken=yes\n[club-account]\ntype=user\nauth=md5\nsecret=fixture-only\ncontext=phone-test\ndeny=0.0.0.0/0.0.0.0\npermit=127.0.0.1/255.255.255.255\n"
        )
        with (
            open(root / "asterisk.log", "w+") as log,
            subprocess.Popen(
                ["asterisk", "-f", "-g", "-C", str(root / "asterisk.conf")],
                stdout=log,
                stderr=log,
            ) as process,
        ):
            try:
                for _ in range(50):
                    assert process.poll() is None, "Asterisk stopped during startup"
                    check = subprocess.run(
                        [
                            "asterisk",
                            "-C",
                            str(root / "asterisk.conf"),
                            "-rx",
                            "iax2 show users",
                        ],
                        capture_output=True,
                        timeout=2,
                        check=False,
                    )
                    if b"club-account" in check.stdout:
                        break
                    time.sleep(0.1)
                else:
                    raise AssertionError("Asterisk provider did not become ready")
                checked = subprocess.run(
                    [
                        str(Path(sys.argv[1]).resolve()),
                        "--provider",
                        f"127.0.0.1:{port}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=True,
                )
                result = json.loads(checked.stdout)
                assert result["echo_samples"] > 0 and result["bad_password_rejected"]
                print(checked.stdout.strip())
            except BaseException:
                log.flush()
                print((root / "asterisk.log").read_text()[-8000:])
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as check:
        check.bind(("127.0.0.1", port))


if __name__ == "__main__":
    main()
