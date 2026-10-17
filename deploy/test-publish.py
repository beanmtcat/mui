#!/usr/bin/env python3
"""Offline publish regression tests. No SSH connection or Docker daemon is used."""
import json
import hashlib
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/publish.sh"


class PublishTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mui-publish-test-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.remote = self.base / "remote with 'quote"
        self.mock = self.base / "commands"
        self.mock.mkdir()
        self.log = self.base / "docker.jsonl"
        self.env = dict(os.environ, PATH=str(self.mock) + os.pathsep + os.environ["PATH"],
                        PUBLISH_MOCK_LOG=str(self.log))
        self.script = SCRIPT
        self.config = self.base / "publish.env"
        self.config.write_text("SSH_HOST=test-target\nREMOTE_DIR=" + shlex.quote(str(self.remote)) +
                               "\nCOMPOSE_PROJECT=mui\nCOMPOSE_FILES=compose.yaml\n")
        self.production = self.base / "production.env"
        self.production.write_text("MUI_SECRET=must-stay-secret\nMUI_DB_PASSWORD=another-secret\n")
        self.command("ssh", r'''
import os, subprocess, sys
args = sys.argv[1:]
while args and args[0].startswith('-'):
    option = args.pop(0)
    if option in ('-p','-o','-i'): args.pop(0)
assert args.pop(0) == 'test-target', args
raise SystemExit(subprocess.call(['bash','-c',args[0]]))
''')
        self.command("docker", r'''
import json, os, sys
args = sys.argv[1:]
with open(os.environ['PUBLISH_MOCK_LOG'],'a') as stream: stream.write(json.dumps(args)+'\n')
if args == ['compose','up','--help']: print('--wait-timeout'); raise SystemExit(0)
failure = os.environ.get('PUBLISH_MOCK_FAIL')
if args and args[0] == 'compose':
    for step in ('build','up','exec'):
        if step in args and failure == step: raise SystemExit(27)
    if 'ps' in args: print('mui-service healthy; mui-web healthy')
''')
        # Linux deployment utilities are mocked only for their platform details.
        # flock is not used to claim concurrency coverage in these offline tests.
        self.command("flock", "raise SystemExit(0)\n")
        self.command("mv", r'''
import os, subprocess, sys
args = sys.argv[1:]
if args and args[0] == '-fT':
    args = args[1:]
    if args[0] == '--': args = args[1:]
    os.replace(*args)
else: raise SystemExit(subprocess.call(['/bin/mv',*args]))
''')

    def command(self, name, body):
        path = self.mock / name
        path.write_text("#!/usr/bin/env python3\n" + body)
        path.chmod(0o755)

    def run_publish(self, *args, ok=True):
        result = subprocess.run(["bash", str(self.script), "--config", str(self.config), *args],
                                cwd=ROOT, env=self.env, capture_output=True, text=True, timeout=30)
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("must-stay-secret", result.stdout + result.stderr)
        self.assertNotIn("another-secret", result.stdout + result.stderr)
        return result

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def initialize(self):
        self.run_publish("--init-env", str(self.production))
        return (self.remote / "current").resolve()

    def test_first_publish_preserves_secrets_and_excludes_local_files(self):
        release = self.initialize()
        remote_env = self.remote / "deploy/.env"
        self.assertEqual(remote_env.read_bytes(), self.production.read_bytes())
        self.assertEqual(stat.S_IMODE(remote_env.stat().st_mode), 0o600)
        self.assertFalse(list(release.rglob(".env")))
        self.assertFalse(list(release.rglob("publish.env")))
        self.assertFalse((release / ".git").exists())
        self.assertFalse((release / "web/node_modules").exists())
        self.assertFalse((release / "deploy/tls").exists())
        self.assertTrue((release / "deploy/compose.yaml").is_file())
        self.assertEqual((release / "bin").resolve(), (self.remote / "bin").resolve())
        self.assertEqual(stat.S_IMODE((self.remote / "bin").stat().st_mode), 0o755)
        builds = [call for call in self.calls() if "build" in call]
        self.assertEqual(builds[-1][-2:], ["mui-service", "mui-web"])
        self.assertTrue(any("exec" in call and call[-1] == "http://127.0.0.1:8086/healthz" for call in self.calls()))

    def test_update_keeps_existing_env_and_only_builds_frontend(self):
        previous = self.initialize()
        before = (self.remote / "deploy/.env").read_bytes()
        self.log.unlink()
        self.run_publish("--service", "frontend")
        self.assertNotEqual((self.remote / "current").resolve(), previous)
        self.assertEqual((self.remote / "deploy/.env").read_bytes(), before)
        for call in self.calls():
            if "build" in call or "up" in call and "--help" not in call:
                self.assertEqual(call[-1], "mui-web")
                self.assertNotIn("mui-service", call)
        self.assertTrue(previous.is_dir())

    def test_init_cannot_overwrite_remote_env(self):
        previous = self.initialize()
        before = (self.remote / "deploy/.env").read_bytes()
        self.production.write_text("MUI_SECRET=changed\n")
        result = self.run_publish("--init-env", str(self.production), ok=False)
        self.assertIn(str(self.remote / "deploy/.env"), result.stderr)
        self.assertEqual((self.remote / "deploy/.env").read_bytes(), before)
        self.assertEqual((self.remote / "current").resolve(), previous)

    def test_missing_env_aborts_before_build(self):
        self.run_publish(ok=False)
        self.assertFalse(any("build" in call for call in self.calls()))
        self.assertFalse((self.remote / "current").exists())

    def test_failed_build_does_not_start_containers_or_switch_current(self):
        previous = self.initialize()
        self.log.unlink()
        self.env["PUBLISH_MOCK_FAIL"] = "build"
        self.run_publish(ok=False)
        self.assertEqual((self.remote / "current").resolve(), previous)
        self.assertFalse(any("up" in call and "--help" not in call for call in self.calls()))
        self.assertFalse(list(self.remote.glob(".publish-*")))

    def test_failed_health_does_not_claim_success_or_switch_current(self):
        previous = self.initialize()
        self.env["PUBLISH_MOCK_FAIL"] = "exec"
        result = self.run_publish(ok=False)
        self.assertNotIn("发布成功", result.stdout)
        self.assertEqual((self.remote / "current").resolve(), previous)

    def agent_fixture(self, corrupt=False):
        source = self.base / "source"
        files = ("go.mod", "go.sum", ".dockerignore", "web/package.json", "web/package-lock.json",
                 "web/tsconfig.json", "web/vite.config.ts", "web/index.html", "deploy/Mui.Dockerfile",
                 "deploy/Web.Dockerfile", "deploy/Agent.Dockerfile", "deploy/build-agent.sh",
                 "deploy/compose.yaml", "deploy/compose.web.yaml", "deploy/compose.backend.yaml",
                 "deploy/.env.example", "deploy/web.env.example", "deploy/publish.env.example")
        for name in files:
            path = source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("fixture")
        for name in ("cmd", "internal", "web/src", "deploy/nginx"):
            (source / name).mkdir(parents=True, exist_ok=True)
        self.script = source / "deploy/publish.sh"
        self.script.write_bytes(SCRIPT.read_bytes())
        artifacts = source / "bin/amd64"
        artifacts.mkdir(parents=True)
        manifest = []
        for name in ("mui-agent", "sing-box"):
            payload = name.encode()
            (artifacts / name).write_bytes(payload)
            manifest.append(hashlib.sha256(payload).hexdigest() + "  " + name)
        (artifacts / "SHA256SUMS").write_text("\n".join(manifest) + "\n")
        (artifacts / "release.key").write_text("never-upload-this-key")
        if corrupt:
            (artifacts / "mui-agent").write_text("wrong checksum")
        self.command("sha256sum", r'''
import hashlib, pathlib
for line in pathlib.Path('SHA256SUMS').read_text().splitlines():
    digest, name = line.split()
    if hashlib.sha256(pathlib.Path(name).read_bytes()).hexdigest() != digest: raise SystemExit(1)
''')

    def test_agent_files_are_checked_and_published_without_private_keys(self):
        self.agent_fixture()
        self.run_publish("--init-env", str(self.production), "--with-agent")
        for name in ("mui-agent", "sing-box", "SHA256SUMS"):
            path = self.remote / "bin/amd64" / name
            self.assertTrue(path.is_file())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
        self.assertFalse(list(self.remote.rglob("release.key")))

    def test_corrupt_agent_aborts_before_image_build(self):
        self.agent_fixture(corrupt=True)
        self.run_publish("--init-env", str(self.production), "--with-agent", ok=False)
        self.assertFalse(any("build" in call for call in self.calls()))
        self.assertFalse((self.remote / "current").exists())

    def test_backend_only_does_not_probe_or_restart_frontend(self):
        self.initialize()
        self.log.unlink()
        self.run_publish("--service", "backend")
        for call in self.calls():
            if "build" in call or "up" in call and "--help" not in call:
                self.assertEqual(call[-1], "mui-service")
                self.assertNotIn("mui-web", call)
        self.assertFalse(any("exec" in call for call in self.calls()))

    def test_dangerous_root_is_rejected(self):
        for path in ("/", "///", "/tmp/..", "/tmp/../mui", "/tmp/."):
            with self.subTest(path=path):
                self.config.write_text("SSH_HOST=test-target\nREMOTE_DIR=" + shlex.quote(path) + "\n")
                self.run_publish(ok=False)

    def test_unquoted_tilde_is_rejected_before_local_expansion(self):
        for assignment in ("REMOTE_DIR=~/docker/mui", "export REMOTE_DIR=~/docker/mui"):
            with self.subTest(assignment=assignment):
                self.config.write_text("SSH_HOST=test-target\n" + assignment + "\n")
                result = self.run_publish("--init-env", str(self.production), ok=False)
                self.assertIn("它会在本机展开", result.stderr)
                self.assertFalse(self.calls())

    def test_reported_directory_matches_the_target(self):
        result = self.run_publish("--init-env", str(self.production))
        self.assertIn("远程发布目录：" + str(self.remote), result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
