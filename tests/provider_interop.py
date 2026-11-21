#!/usr/bin/env python3
"""Independent loopback provider acceptance using the actual C header/DSO.

The quality image supplies a test-only Asterisk; installed IAX media is PBX-free.
"""

import argparse
import json
import select
import socket
import subprocess
import tempfile
import time
from pathlib import Path


def listener_fixture(
    binary,
    port,
    configuration,
    codec="ulaw",
    configured=False,
    jitter=None,
    mixed=False,
    live=False,
):
    """Actual public server tails, dynamic provider calls, and exact owned cleanup."""
    if jitter is None:
        [jitter] = Path("/usr/lib").glob("*/rpt_advanced/librptadv_jitter_adapter.so.1")
    args = [str(Path(binary).resolve()), f"127.0.0.1:{port}", codec, str(jitter)]
    if live:
        args.append("live")
    elif mixed:
        args.append("mixed")
    elif configured:
        args.append("configured")
    with subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ) as fixture:
        try:
            ready, _, _ = select.select([fixture.stdout], [], [], 10)
            assert ready, "provider listener did not register and finish outgoing media"
            first_line = fixture.stdout.readline()
            assert first_line, fixture.communicate(timeout=2)[1]
            first = json.loads(first_line)
            assert first["ready"] and first["outgoing_echo_samples"] > 0
            assert first["format"] == (8 if codec == "alaw" else 4)
            assert first["initial_jitter_samples"] == (680 if configured else 320)
            originated = subprocess.run(
                [
                    "asterisk",
                    "-C",
                    str(configuration),
                    "-rx",
                    "channel originate IAX2/club-account/incoming-extension application Echo",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=True,
            )
            remaining, errors = fixture.communicate(timeout=12)
            assert fixture.returncode == 0, originated.stdout + errors
            if live:
                assert (
                    "native live policy queued=" in errors
                    and "restore=1 attached=1" in errors
                )
                print(errors.strip())
            final = json.loads(remaining)
            assert final["outgoing_echo_samples"] > 0
            assert final["incoming_echo_samples"] > 0
            assert final["released"] and final["bad_secret_rejected"]
            assert final["port_rebound"]
            assert final["format"] == first["format"]
            assert final["incoming_initial_jitter_samples"] == (
                680 if configured or mixed or live else 320
            )
            print(json.dumps(first))
            print(json.dumps(final))
        finally:
            if fixture.poll() is None:
                fixture.terminate()
                try:
                    fixture.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    fixture.kill()
                    fixture.wait(timeout=2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("client", nargs="?")
    parser.add_argument("listener")
    parser.add_argument("--configured-listener-only", action="store_true")
    parser.add_argument("--live-listener-only", action="store_true")
    parser.add_argument("--jitter", type=Path)
    args = parser.parse_args()
    if (
        not args.configured_listener_only
        and not args.live_listener_only
        and not args.client
    ):
        parser.error("full provider qualification requires a client and listener")
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
            "[modules]\nautoload=no\nload=chan_iax2.so\nload=pbx_config.so\nload=codec_ulaw.so\nload=codec_alaw.so\nload=app_echo.so\nload=res_clioriginate.so\n"
        )
        (root / "logger.conf").write_text(
            "[logfiles]\nconsole => notice,warning,error,debug,verbose\n"
        )
        (root / "extensions.conf").write_text(
            "[phone-test]\nexten => 999,1,Answer()\nsame => n,Echo()\nsame => n,Hangup()\n"
        )
        (root / "iax.conf").write_text(
            f"[general]\nbindport={port}\nbindaddr=127.0.0.1\ndisallow=all\nallow=ulaw\n[club-account]\ntype=friend\nhost=dynamic\nusername=club-account\nrequirecalltoken=yes\nauth=md5\nsecret=fixture-only\ncontext=phone-test\ndeny=0.0.0.0/0.0.0.0\npermit=127.0.0.1/255.255.255.255\n"
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
                if args.live_listener_only:
                    listener_fixture(
                        args.listener,
                        port,
                        root / "asterisk.conf",
                        live=True,
                        jitter=args.jitter,
                    )
                elif args.configured_listener_only:
                    listener_fixture(
                        args.listener,
                        port,
                        root / "asterisk.conf",
                        configured=True,
                        jitter=args.jitter,
                    )
                    listener_fixture(
                        args.listener,
                        port,
                        root / "asterisk.conf",
                        mixed=True,
                        jitter=args.jitter,
                    )
                else:
                    checked = subprocess.run(
                        [
                            str(Path(args.client).resolve()),
                            "--provider",
                            f"127.0.0.1:{port}",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=15,
                        check=True,
                    )
                    result = json.loads(checked.stdout)
                    assert (
                        result["echo_samples"] > 0 and result["bad_password_rejected"]
                    )
                    print(checked.stdout.strip())
                    listener_fixture(
                        args.listener, port, root / "asterisk.conf", jitter=args.jitter
                    )
                    # The same independent registrar now accepts PCMA only. A new
                    # listener/account owns its own exact port and codec contexts.
                    iax = root / "iax.conf"
                    iax.write_text(iax.read_text().replace("allow=ulaw", "allow=alaw"))
                    subprocess.run(
                        [
                            "asterisk",
                            "-C",
                            str(root / "asterisk.conf"),
                            "-rx",
                            "iax2 reload",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=3,
                        check=True,
                    )
                    listener_fixture(
                        args.listener,
                        port,
                        root / "asterisk.conf",
                        "alaw",
                        jitter=args.jitter,
                    )
                    listener_fixture(
                        args.listener,
                        port,
                        root / "asterisk.conf",
                        "alaw",
                        configured=True,
                        jitter=args.jitter,
                    )
                    listener_fixture(
                        args.listener,
                        port,
                        root / "asterisk.conf",
                        "alaw",
                        mixed=True,
                        jitter=args.jitter,
                    )
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
