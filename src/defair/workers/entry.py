"""Worker job runner — ``python -m defair.workers.entry /workspace/jobs/<RUN>/job.json``.

Runs the steps of a job spec written by the case container, one after the
other, as argv lists (never through a shell), and records everything in
``status.json`` next to the spec (atomically, after every step):

- ``skip``: step not needed (e.g. ``.plaso`` storage reused) — recorded;
- ``stdout``: file receiving the tool's standard output (``fls`` bodyfile);
- ``parse: mmls``: the output lists partitions; later ``for_each: partition``
  steps run once per partition with ``{offset}`` / ``{index}`` substituted;
- ``strings_to``: the tool's standard output is streamed into the strings
  extractor (``blkls`` → unallocated strings TSV), never stored raw;
- ``try: {"fstype": [...]}``: the step is attempted with each value in turn
  (``{fstype}`` substituted) until one succeeds — Sleuth Kit's filesystem
  autodetection is not relied upon; the partition's ``mmls`` description
  puts the likely type first;
- ``allow_failure``: a failing step does not fail the job;
- ``hash``: files hashed (SHA-256) at the end, recorded in the status.

SIGTERM (``docker stop``) kills the running tool and records ``cancelled``.
Logs are JSON lines in ``/workspace/logs/defair.log``, the file the case
container's PID 1 follows, so ``docker logs`` shows the job as well.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

LOG_FILE = Path(os.environ.get("DEFAIR_WORKSPACE", "/workspace")) / "logs" / "defair.log"
VERSIONS_FILE = Path("/opt/defair/versions.json")
STDERR_TAIL = 4000


def _now() -> str:
    return datetime.now(UTC).isoformat()


class Runner:
    def __init__(self, spec_path: Path) -> None:
        self.spec_path = spec_path
        self.spec = json.loads(spec_path.read_text())
        self.status_path = spec_path.parent / "status.json"
        self.run = self.spec.get("run_number", "RUN-?")
        self.proc: subprocess.Popen | None = None
        self.cancelled = False
        self.deadline = time.monotonic() + int(os.environ.get("DEFAIR_JOB_TIMEOUT", "43200"))
        self.status: dict = {
            "run_number": self.run, "worker": self.spec.get("worker"), "state": "running",
            "started_at": _now(), "steps": [], "partitions": [], "hashes": {},
            "versions": self._versions(),
        }

    @staticmethod
    def _versions() -> dict:
        try:
            return json.loads(VERSIONS_FILE.read_text())
        except (OSError, ValueError):
            return {}

    def log(self, event: str, level: str = "info", **fields) -> None:
        line = {"timestamp": _now(), "level": level, "event": event, "component": "worker",
                "run": self.run, **fields}
        print(json.dumps(line, default=str), file=sys.stderr, flush=True)
        try:
            LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(line, default=str) + "\n")
        except OSError:
            pass

    def save(self) -> None:
        self.status["updated_at"] = _now()
        tmp = self.status_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.status, indent=2, default=str))
        tmp.replace(self.status_path)

    def on_term(self, *_):
        self.cancelled = True
        if self.proc and self.proc.poll() is None:
            self.proc.kill()

    # -- steps --------------------------------------------------------------

    def expand(self, step: dict) -> list[dict]:
        if step.get("for_each") != "partition":
            return [step]
        partitions = self.status["partitions"] or [{"index": 0, "offset": 0, "description": "whole image"}]
        out = []
        for partition in partitions:
            values = {"offset": partition["offset"], "index": partition["index"]}
            out.append({
                **step,
                "name": f"{step['name']}[{partition['index']}]",
                "argv": [substitute(a, values) for a in step["argv"]],
                "stdout": substitute(step["stdout"], values) if step.get("stdout") else None,
                "strings_to": substitute(step["strings_to"], values) if step.get("strings_to") else None,
                "partition": partition,
            })
        return out

    def run_with_alternatives(self, step: dict) -> dict:
        tries = step.get("try") or {}
        if not tries:
            return self.run_step(step)
        (key, values), = tries.items()
        values = order_fs_types(values, (step.get("partition") or {}).get("description", ""))
        attempts = []
        record: dict = {}
        for value in values:
            values = {key: value}
            attempt = {**step, "argv": [substitute(a, values) for a in step["argv"]],
                       "name": f"{step['name']}:{value}", "allow_failure": True}
            if step.get("stdout"):
                attempt["stdout"] = substitute(step["stdout"], values)
            if step.get("strings_to"):
                attempt["strings_to"] = substitute(step["strings_to"], values)
            record = self.run_step(attempt)
            attempts.append({"value": value, "exit_code": record.get("exit_code")})
            if record["state"] in ("completed", "cancelled"):
                break
            for leftover in (attempt.get("stdout"), attempt.get("strings_to")):
                if leftover:
                    Path(leftover).unlink(missing_ok=True)
        last = record.get("state")
        if last not in ("completed", "cancelled"):
            last = "tolerated" if step.get("allow_failure") else "failed"
        return {**record, "name": step["name"], "attempts": attempts, "state": last,
                key: attempts[-1]["value"] if last == "completed" else None}

    def run_step(self, step: dict) -> dict:
        record = {"name": step["name"], "argv": step["argv"], "started_at": _now()}
        if step.get("skip"):
            record.update(state="skipped", reason=step.get("skip_reason", ""))
            self.log("worker_step_skipped", step=step["name"], reason=record["reason"])
            return record
        timeout = min(step.get("timeout") or 1e9, max(1, self.deadline - time.monotonic()))
        self.log("worker_step_started", step=step["name"], argv=step["argv"])
        start = time.monotonic()
        stdout_target = None
        if step.get("stdout"):
            Path(step["stdout"]).parent.mkdir(parents=True, exist_ok=True)
            stdout_target = open(step["stdout"], "wb")  # noqa: SIM115 — closed below
        # stderr goes to a file: a chatty tool must never block on a full pipe
        # while its stdout is being streamed
        stderr_file = tempfile.TemporaryFile()  # noqa: SIM115 — closed in finally
        try:
            self.proc = subprocess.Popen(
                step["argv"], stdin=subprocess.DEVNULL,
                stdout=stdout_target or subprocess.PIPE, stderr=stderr_file,
                cwd=step.get("cwd") or None,
            )
            stdout_text = ""
            if step.get("strings_to"):
                record["strings"] = self._stream_strings(self.proc.stdout, step)
            try:
                out, _ = self.proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                out, _ = self.proc.communicate()
                record["timed_out"] = True
            if out and not stdout_target:
                stdout_text = out.decode(errors="replace")
            record["exit_code"] = self.proc.returncode
            stderr_file.seek(0, 2)
            stderr_file.seek(max(0, stderr_file.tell() - STDERR_TAIL))
            record["stderr_tail"] = stderr_file.read().decode(errors="replace")
            if step.get("parse") == "mmls":
                self._partitions(stdout_text, record)
        except FileNotFoundError:
            record.update(exit_code=127, stderr_tail=f"tool not found: {step['argv'][0]}")
        finally:
            if stdout_target:
                stdout_target.close()
            stderr_file.close()
            self.proc = None
        record["duration_seconds"] = round(time.monotonic() - start, 3)
        ok = record.get("exit_code") in step.get("success_exit_codes", [0]) and not record.get("timed_out")
        if self.cancelled:
            record["state"] = "cancelled"
        else:
            record["state"] = "completed" if ok else ("tolerated" if step.get("allow_failure") else "failed")
        self.log("worker_step_finished", step=step["name"], state=record["state"],
                 exit_code=record.get("exit_code"), duration=record["duration_seconds"],
                 stderr_tail=record.get("stderr_tail", "")[-500:] or None)
        return record

    def _partitions(self, output: str, record: dict) -> None:
        from defair.workers.tsk import parse_mmls

        sector, partitions = parse_mmls(output)
        self.status["sector_size"] = sector
        self.status["partitions"] = partitions
        record["partitions"] = len(partitions)
        if record.get("exit_code") != 0:
            record["exit_code"] = 0  # no partition table: the image is one volume
            record["note"] = "no partition table: whole image used as one volume"

    def _stream_strings(self, stream, step: dict) -> dict:
        from defair.workers.strings import extract_strings

        target = Path(step["strings_to"])
        target.parent.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256()
        count = 0
        with target.open("w", encoding="utf-8") as fo:
            for offset, encoding, text in extract_strings(stream, int(step.get("min_length", 6))):
                line = f"{offset}\t{encoding}\t{text}\n"
                fo.write(line)
                digest.update(line.encode("utf-8"))
                count += 1
        return {"tsv": str(target), "strings": count, "sha256": digest.hexdigest()}

    def main(self) -> int:
        try:
            return self._main()
        except Exception as e:  # noqa: BLE001 — recorded, never a silent crash
            self.status.update(state="failed", error=f"runner error: {type(e).__name__}: {e}",
                               completed_at=_now())
            self.save()
            self.log("worker_job_crashed", level="error", error=str(e))
            return 1

    def _main(self) -> int:
        signal.signal(signal.SIGTERM, self.on_term)
        self.log("worker_job_started", worker=self.spec.get("worker"), steps=len(self.spec.get("steps", [])))
        self.save()
        failed = None
        for template in self.spec.get("steps", []):
            for step in self.expand(template):
                if self.cancelled or time.monotonic() > self.deadline:
                    break
                record = self.run_with_alternatives(step)
                self.status["steps"].append(record)
                self.save()
                if record["state"] == "failed" and not step.get("allow_failure"):
                    failed = f"step {step['name']} failed (exit {record.get('exit_code')})"
                    break
            if failed or self.cancelled or time.monotonic() > self.deadline:
                break
        if not failed and not self.cancelled:
            for path in self.spec.get("hash", []):
                self.status["hashes"][path] = sha256_file(Path(path))
        if self.cancelled:
            self.status["state"] = "cancelled"
        elif time.monotonic() > self.deadline:
            self.status.update(state="failed", error="job timeout")
        elif failed:
            self.status.update(state="failed", error=failed)
        else:
            self.status["state"] = "completed"
        self.status["completed_at"] = _now()
        self.save()
        self.log("worker_job_finished", state=self.status["state"], error=self.status.get("error"))
        return 0 if self.status["state"] == "completed" else 1


def substitute(text: str, values: dict) -> str:
    """Replace ``{name}`` placeholders present in ``values``; leave the others."""
    for name, value in values.items():
        text = text.replace("{" + name + "}", str(value))
    return text


FS_HINTS = (("ntfs", "ntfs"), ("exfat", "exfat"), ("fat", "fat"), ("linux", "ext"),
            ("ext", "ext"), ("hfs", "hfs"), ("apple", "hfs"), ("iso", "iso9660"))


def order_fs_types(values: list[str], description: str) -> list[str]:
    """Likely filesystem type first, from the partition's ``mmls`` description."""
    lower = description.lower()
    preferred = [fs for hint, fs in FS_HINTS if hint in lower and fs in values]
    return list(dict.fromkeys([*preferred, *values]))


def sha256_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print("usage: python -m defair.workers.entry /workspace/jobs/<RUN>/job.json", file=sys.stderr)
        return 2
    return Runner(Path(argv[0])).main()


if __name__ == "__main__":
    sys.exit(main())
