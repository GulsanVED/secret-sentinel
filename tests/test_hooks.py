"""
Tests for the git hooks in .githooks/: they run through real `git commit` and
`git push` calls against a local bare "remote", exactly as a developer would.

Run:  python3 -m tests.test_hooks      (needs git and sh; no other dependencies)
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

FAILURES = []
PROJECT = Path(__file__).resolve().parent.parent
AWS_KEY = "AKIAQWERTYUIOPASDFGH"          # fake, but the right shape


def check(label, cond, detail=""):
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f"  ({detail})" if detail and not cond else ""))
    if not cond:
        FAILURES.append(label)


class Repo:
    def __init__(self):
        tmp = Path(tempfile.mkdtemp())
        self.remote = tmp / "remote.git"
        self.root = tmp / "work"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(self.remote)], check=True)
        subprocess.run(["git", "clone", "-q", str(self.remote), str(self.root)], check=True,
                       capture_output=True)
        # CI runners set these; the hooks must scan this repo, not the runner's commit.
        self.env = {k: v for k, v in os.environ.items()
                    if k not in ("GITHUB_ACTIONS", "GITHUB_STEP_SUMMARY", "GITHUB_SHA", "GIT_COMMIT")}
        self.env.update(SENTINEL_HOME=str(PROJECT), PYTHONPATH="")
        self.git("config", "user.email", "dev@example.com")
        self.git("config", "user.name", "Dev")
        self.git("config", "core.hooksPath", str(PROJECT / ".githooks"))
        self.git("switch", "-q", "-c", "main")

    def git(self, *args, env=None):
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True,
                              env=env or self.env)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message, *files, extra=()):
        self.git("add", *(files or ["-A"]))
        return self.git("commit", "-q", "-m", message, *extra)

    def head_subject(self):
        return self.git("log", "-1", "--format=%s").stdout.strip()


def main():
    print("1) Hooks are executable and wired up")
    for name in ("pre-commit", "pre-push"):
        check(f"{name} is executable", os.access(PROJECT / ".githooks" / name, os.X_OK))

    repo = Repo()
    repo.write("app.py", "import os\nKEY = os.environ['API_KEY']\n")
    r = repo.commit("clean start")
    check("a clean commit goes through", r.returncode == 0 and repo.head_subject() == "clean start",
          r.stderr[-300:])
    r = repo.git("push", "-q", "-u", "origin", "main")
    check("a clean first push goes through", r.returncode == 0, r.stderr[-300:])

    print("2) pre-commit: .env files")
    repo.write(".env", "DB_PASSWORD=Hunter2Secret\n")
    r = repo.commit("add env", ".env")
    check("committing .env is blocked", r.returncode != 0 and "must not be committed" in r.stderr,
          r.stderr[-300:])
    check("the blocked commit did not happen", repo.head_subject() == "clean start")
    repo.git("rm", "-q", "--cached", ".env")
    (repo.root / ".env").unlink()
    repo.write(".env.example", "DB_PASSWORD=changeme\n")
    r = repo.commit("add env template", ".env.example")
    check(".env.example is allowed", r.returncode == 0, r.stderr[-300:])

    print("3) pre-commit: secrets in the staged lines")
    repo.write("deploy.py", f'aws = "{AWS_KEY}"\n')
    r = repo.commit("add deploy", "deploy.py")
    check("a staged AWS key blocks the commit",
          r.returncode != 0 and "aws-access-key-id" in r.stdout + r.stderr, (r.stdout + r.stderr)[-400:])
    check("the key is masked in the message", AWS_KEY not in r.stdout + r.stderr)
    check("nothing was committed", repo.head_subject() == "add env template")
    repo.write("deploy.py", f'aws = "{AWS_KEY}"  # sentinel:ignore\n')
    r = repo.commit("fixture", "deploy.py")
    check("# sentinel:ignore lets a fixture through", r.returncode == 0, r.stderr[-300:])
    repo.write("deploy.py", "aws = os.environ['AWS_KEY']\n")
    r = repo.commit("read from env", "deploy.py")
    check("removing a secret line is never blocked", r.returncode == 0, r.stderr[-300:])

    print("4) pre-push: commits that skipped pre-commit")
    repo.write("leak.py", f'aws = "{AWS_KEY}"\n')
    r = repo.commit("leak", "leak.py", extra=("--no-verify",))
    check("--no-verify skips pre-commit (hooks are optional)", r.returncode == 0, r.stderr[-300:])
    repo.write("leak.py", "aws = None\n")
    r = repo.commit("remove leak", "leak.py")
    check("a later commit can remove it", r.returncode == 0, r.stderr[-300:])
    r = repo.git("push", "-q", "origin", "main")
    check("push is blocked: the secret is still in an unpushed commit",
          r.returncode != 0 and "Push blocked" in r.stderr and "HISTORY ONLY" in r.stdout + r.stderr,
          (r.stdout + r.stderr)[-500:])
    remote_head = subprocess.run(["git", "-C", str(repo.remote), "log", "-1", "--format=%s", "main"],
                                 capture_output=True, text=True).stdout.strip()
    check("the remote did not receive it", remote_head == "clean start", remote_head)

    r = repo.git("push", "-q", "--no-verify", "origin", "main")
    check("--no-verify skips pre-push too", r.returncode == 0, r.stderr[-300:])

    print("5) pre-push scans only what is new")
    repo.git("switch", "-q", "-c", "feature")
    repo.write("feature.py", "print('ok')\n")
    repo.commit("feature")
    r = repo.git("push", "-q", "-u", "origin", "feature")
    check("a new branch with clean commits pushes, although main's history has a secret",
          r.returncode == 0, (r.stdout + r.stderr)[-400:])
    r = repo.git("push", "-q", "origin", "--delete", "feature")
    check("deleting a remote branch is never blocked", r.returncode == 0, r.stderr[-300:])

    print("6) The CLI commands behind the hooks")
    repo.write("x.py", f'k = "{AWS_KEY}"\n')
    repo.git("add", "x.py")
    out = subprocess.run([sys.executable, str(PROJECT / "ci_scan.py"), "scan-staged", str(repo.root),
                          "--json", "--fail-on", "none"], capture_output=True, text=True, env=repo.env)
    data = json.loads(out.stdout)
    check("scan-staged reports the staged line with its line number",
          [(f["file_path"], f["line_number"]) for f in data["findings"]] == [("x.py", 1)], data["findings"])
    check("scan-staged mode is 'staged'", data.get("mode") == "staged", data.get("mode"))
    repo.git("reset", "-q", "x.py")
    (repo.root / "x.py").unlink()
    repo.git("switch", "-q", "main")          # fully pushed (feature's remote copy was deleted above)
    out = subprocess.run([sys.executable, str(PROJECT / "ci_scan.py"), "scan-history", str(repo.root),
                          "--unpushed", "--json", "--fail-on", "none"], capture_output=True, text=True,
                         env=repo.env)
    data = json.loads(out.stdout)
    check("--unpushed with everything pushed scans no commits", data.get("commits_scanned") == 0, data)

    print("7) Missing scanner: warn, don't block")
    env = {**repo.env, "SENTINEL_HOME": "/nonexistent"}
    repo.write("y.py", "y = 1\n")
    repo.git("add", "y.py")
    r = repo.git("commit", "-q", "-m", "no scanner", env=env)
    check("commit allowed with a warning when Secret Sentinel is not found",
          r.returncode == 0 and "not scanned" in r.stderr, r.stderr[-300:])

    print(f"\n{'ALL PASSED' if not FAILURES else f'{len(FAILURES)} FAILED: {FAILURES}'}")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
