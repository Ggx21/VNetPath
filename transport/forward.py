import argparse
from contextlib import suppress
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import sys


def receiver(args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", args.center):
        raise ValueError("expected an SSH host alias")
    if not args.directory.startswith("/") or not args.database.startswith("/"):
        raise ValueError("specify absolute paths on the center")
    command = shlex.join(["python3", "-m", "collector", "--database", args.database,
                          "receive", "--", args.session, args.device])
    return ["ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", "ConnectTimeout=10", args.center, f"cd {shlex.quote(args.directory)} && exec {command}"]


def capture(args, channel):
    native = [str(args.agent.resolve()), "--device", args.device, "--object", str(args.object.resolve()),
              *args.interfaces]
    with args.spool.open("xb") as spool, subprocess.Popen(native, stdout=subprocess.PIPE,
                                                          start_new_session=True) as agent:
        def stop(signum, frame):
            agent.terminate()

        handlers = {sig: signal.signal(sig, stop) for sig in (signal.SIGINT, signal.SIGTERM)}
        online = True
        try:
            for line in agent.stdout:
                spool.write(line)
                spool.flush()
                if online:
                    try:
                        channel.write(line)
                        channel.flush()
                    except BrokenPipeError:
                        online = False
                        print("Center disconnected; continuing capture to local spool.", file=sys.stderr)
            if agent.wait():
                raise ValueError("capture failed; the session remains incomplete")
            end = b'{"stream_end":true}\n'
            spool.write(end)
            spool.flush()
            os.fsync(spool.fileno())
            if online:
                channel.write(end)
        finally:
            for sig, previous in handlers.items():
                signal.signal(sig, previous)
            if agent.poll() is None:
                agent.terminate()


def main():
    parser = argparse.ArgumentParser(description="Forward a host's probe events over the management connection.")
    parser.add_argument("--center", required=True, help="SSH host alias")
    parser.add_argument("--directory", required=True, help="repository directory on the center")
    parser.add_argument("--database", required=True, help="session database on the center")
    parser.add_argument("--session", required=True)
    parser.add_argument("--device", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    live = commands.add_parser("capture", help="stream the Linux agent and retain a local copy")
    live.add_argument("--agent", type=Path, required=True, help="vnetpath-agent executable")
    live.add_argument("--object", type=Path, required=True, help="compiled BPF object")
    live.add_argument("--spool", type=Path, required=True, help="new local file for replay")
    live.add_argument("interfaces", nargs="+")
    replay = commands.add_parser("send", help="resend an existing spool after a connection failure")
    replay.add_argument("spool", type=Path)
    args = parser.parse_args()
    try:
        with subprocess.Popen(receiver(args), stdin=subprocess.PIPE) as ssh:
            try:
                if args.command == "capture":
                    capture(args, ssh.stdin)
                else:
                    with args.spool.open("rb") as stream:
                        shutil.copyfileobj(stream, ssh.stdin)
            finally:
                with suppress(BrokenPipeError):
                    ssh.stdin.close()
            if ssh.wait():
                raise ValueError("the center did not acknowledge this stream")
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(2, f"{parser.prog}: {error}\n")


if __name__ == "__main__":
    main()
