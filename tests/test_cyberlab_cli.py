"""The cyberlab CLI's cleanup commands (skills/cyberlab/scripts/cyberlab): down, status, nuke, --help.

Run from the repo root: python3 -m unittest discover -s tests
A case puts tests/fake_docker.sh on PATH as `docker`: it logs every call to <state>/log and answers
from fixture files <state>/{containers,networks,volumes,images} (<id> <name|-> <project>), mutating
`images` on `compose down --rmi` (Compose before v5.5.1: only the project's tagged images go) and on
`image rm`. Assertions are on exact log lines present or absent, never on whole-log equality (GNU
xargs runs once on empty input, BSD xargs does not). Each case runs once per bash found."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

TESTS = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(TESTS, "..", "skills", "cyberlab", "scripts", "cyberlab")
FAKE_DOCKER = os.path.join(TESTS, "fake_docker.sh")

F1 = {
    "containers": "c1 cyberlab-a-victim-1 cyberlab-a\n",
    "networks": "n1 cyberlab-a_labnet cyberlab-a\nn9 other_default otherproj\n",
    "volumes": "cyberlab-a_data cyberlab-a\n",
}
F2 = {
    "images": "i1 cyberlab-a-victim:latest cyberlab-a\ni2 - cyberlab-a\n"
              "i3 cyberlab-ab-victim:latest cyberlab-ab\ni9 otherproj-web:latest otherproj\n",
}
FIXTURES = {"F0": {}, "F1": F1, "F2": F2, "F3": {**F1, **F2}}

RESOURCE_ROWS = ["container cyberlab-a-victim-1 cyberlab-a",
                 "network cyberlab-a_labnet cyberlab-a",
                 "volume cyberlab-a_data cyberlab-a"]
IMAGE_ROWS = ["image cyberlab-a-victim:latest cyberlab-a",
              "image sha256:i2 cyberlab-a",
              "image cyberlab-ab-victim:latest cyberlab-ab"]


def _bashes():
    seen, found = set(), []
    for path in ("/bin/bash", shutil.which("bash")):
        if path and os.path.exists(path):
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                found.append(path)
    return found


def _lines(path):
    """The lines of a fixture or log file; [] when it does not exist."""
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return f.read().splitlines()


BASHES = _bashes()
CLEAN_ENV = ("CYBERLAB_TOOLS", "CYBERLAB_TIMEOUT", "CYBERLAB_HOME", "MODE", "PCAP")


@unittest.skipIf(shutil.which("bash") is None, "no bash on PATH")
class CyberlabCli(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="cyberlab-cli-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        docker = os.path.join(self.bin, "docker")
        shutil.copy(FAKE_DOCKER, docker)
        os.chmod(docker, 0o755)
        # the fake `docker run ... <tools image> python3 -c ...` execs the command: give it a python3
        os.symlink(sys.executable, os.path.join(self.bin, "python3"))
        self.state = os.path.join(self.tmp, "state")
        self.labA = os.path.join(self.tmp, "labA")
        self.labB = os.path.join(self.tmp, "labB")
        for lab in (self.labA, self.labB):
            os.makedirs(lab)
            with open(os.path.join(lab, "docker-compose.yml"), "w") as f:
                f.write("name: cyberlab-a\n")
        self.env = dict(os.environ)
        self.env["PATH"] = self.bin + os.pathsep + self.env.get("PATH", "")
        self.env["STUB_DIR"] = self.state
        self.env["STUB_PROJECT"] = "cyberlab-a"
        for var in CLEAN_ENV:
            self.env.pop(var, None)

    def fixture(self, name):
        """Reset <state> to a fresh copy of fixture Fn (an absent file means none) plus the log."""
        shutil.rmtree(self.state, ignore_errors=True)
        os.makedirs(self.state)
        for fname, content in FIXTURES[name].items():
            with open(os.path.join(self.state, fname), "w") as f:
                f.write(content)

    def cli(self, bash, args, extra_env=None):
        env = dict(self.env)
        if extra_env:
            env.update(extra_env)
        p = subprocess.run([bash, CLI] + args, env=env, capture_output=True, text=True)
        return p.returncode, p.stdout, p.stderr, _lines(os.path.join(self.state, "log"))

    def images(self):
        return _lines(os.path.join(self.state, "images"))

    @staticmethod
    def rm_lines(log):
        return [l for l in log if l.startswith(("rm ", "network rm", "volume rm", "image rm"))]

    def each_bash(self, check):
        for bash in BASHES:
            with self.subTest(bash=bash):
                check(bash)

    def test_status_nothing(self):
        def check(bash):
            self.fixture("F0")
            rc, out, err, log = self.cli(bash, ["status"])
            self.assertEqual(0, rc, err)
            self.assertEqual("no cyberlab lab resources\n", out)
        self.each_bash(check)

    def test_status_resources_only(self):
        def check(bash):
            self.fixture("F1")
            rc, out, err, log = self.cli(bash, ["status"])
            self.assertEqual(0, rc, err)
            self.assertEqual(RESOURCE_ROWS, out.splitlines())
        self.each_bash(check)

    def test_status_images_only(self):
        def check(bash):
            self.fixture("F2")
            rc, out, err, log = self.cli(bash, ["status"])
            self.assertEqual(0, rc, err)
            lines = out.splitlines()
            self.assertEqual(IMAGE_ROWS, lines[:3])
            self.assertEqual(4, len(lines))
            self.assertTrue(lines[3].startswith(
                "NOTE no container, network or volume left; 3 built image(s) kept"), out)
            self.assertNotIn("otherproj", out)
        self.each_bash(check)

    def test_status_resources_and_images(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["status"])
            self.assertEqual(0, rc, err)
            self.assertEqual(RESOURCE_ROWS + IMAGE_ROWS, out.splitlines())
        self.each_bash(check)

    def test_status_one_lab(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["status", self.labA])
            self.assertEqual(0, rc, err)
            self.assertEqual(RESOURCE_ROWS + IMAGE_ROWS[:2], out.splitlines())
            self.assertNotIn("cyberlab-ab", out)
        self.each_bash(check)

    def test_down_usage_errors(self):
        cases = [
            (["down"], "usage: cyberlab down <lab> [--images]"),
            (["down", "--images"], "usage: cyberlab down <lab> [--images]"),
            (["down", self.labA, self.labB], "usage: cyberlab down <lab> [--images]"),
            (["down", self.labA, "--bogus"], "down: unknown option '--bogus'."),
        ]
        def check(bash):
            for args, msg in cases:
                self.fixture("F3")
                rc, out, err, log = self.cli(bash, args)
                self.assertEqual(1, rc, err)
                self.assertIn(msg, err)
                self.assertFalse(any(l.startswith("compose down") for l in log), log)
        self.each_bash(check)

    def test_down_no_lab_dir(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["down", os.path.join(self.tmp, "nolab")])
            self.assertEqual(1, rc, err)
            self.assertIn("no docker-compose.yml in", err)
            self.assertFalse(any(l.startswith("compose down") for l in log), log)
        self.each_bash(check)

    def test_down_keeps_images(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["down", self.labA])
            self.assertEqual(0, rc, err)
            self.assertEqual("PASS down %s\n" % self.labA, out)
            self.assertIn("compose down -v --remove-orphans", log)
            self.assertFalse(any(l.startswith(("image rm", "image ls", "run ")) for l in log), log)
            self.assertEqual(FIXTURES["F3"]["images"].splitlines(), self.images())
        self.each_bash(check)

    def test_down_images_removes_untagged_leftovers(self):
        def check(bash):
            for args in (["down", self.labA, "--images"], ["down", "--images", self.labA]):
                self.fixture("F3")
                rc, out, err, log = self.cli(bash, args)
                self.assertEqual(0, rc, err)
                self.assertIn("compose down -v --remove-orphans --rmi local", log)
                self.assertIn("image rm i2", log)
                for line in self.rm_lines(log):
                    self.assertNotIn("i3", line.split())
                    self.assertNotIn("i9", line.split())
                self.assertEqual("PASS down %s (built images removed)" % self.labA,
                                 out.splitlines()[-1])
                left = self.images()
                self.assertFalse(any(l.split()[-1] == "cyberlab-a" for l in left), left)
                ids = [l.split()[0] for l in left]
                self.assertIn("i3", ids)
                self.assertIn("i9", ids)
        self.each_bash(check)

    def test_down_images_reports_what_is_left(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["down", self.labA, "--images"],
                                         {"STUB_IMAGE_RM_FAILS": "1"})
            self.assertEqual(2, rc, err)
            self.assertIn("could not be removed", err)
            self.assertIn("i2", err)
            self.assertNotIn("PASS", out)
        self.each_bash(check)

    def test_down_images_needs_project_name(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["down", self.labA, "--images"],
                                         {"STUB_PROJECT": "other"})
            self.assertEqual(2, rc, err)
            self.assertIn("cannot read the lab's project name", err)
            self.assertFalse(any(l.startswith("compose down") for l in log), log)
        self.each_bash(check)

    def test_down_images_needs_tools_image(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["down", self.labA, "--images"],
                                         {"STUB_NO_TOOLS": "1"})
            self.assertEqual(1, rc, err)
            self.assertIn("tools image", err)
            self.assertFalse(any(l.startswith("compose down") for l in log), log)
        self.each_bash(check)

    def test_down_compose_failure(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["down", self.labA, "--images"],
                                         {"STUB_DOWN_RC": "1"})
            self.assertEqual(2, rc, err)
            self.assertIn("docker compose down failed in", err)
            self.assertNotIn("PASS", out)
            self.assertFalse(any(l.startswith("image rm") for l in log), log)
        self.each_bash(check)

    def test_nuke_rejects_arguments(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["nuke", "bogus"])
            self.assertEqual(1, rc, err)
            self.assertIn("nuke: unknown option 'bogus'", err)
            self.assertEqual([], self.rm_lines(log), log)
        self.each_bash(check)

    def test_nuke_keeps_images(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["nuke"])
            self.assertEqual(0, rc, err)
            for line in ("rm -f c1", "network rm n1", "volume rm cyberlab-a_data"):
                self.assertIn(line, log)
            self.assertFalse(any(l.startswith("image rm") for l in log), log)
            for line in self.rm_lines(log):
                self.assertNotIn("n9", line.split())
            self.assertIn("removed cyberlab-a", out)
            self.assertIn("PASS nuke", out)
            self.assertNotIn("removed cyberlab-ab", out)
        self.each_bash(check)

    def test_nuke_images(self):
        def check(bash):
            self.fixture("F3")
            rc, out, err, log = self.cli(bash, ["nuke", "--images"])
            self.assertEqual(0, rc, err)
            for line in ("rm -f c1", "network rm n1", "volume rm cyberlab-a_data",
                         "image rm -f i1 i2", "image rm -f i3"):
                self.assertIn(line, log)
            for line in self.rm_lines(log):
                self.assertNotIn("i9", line.split())
                self.assertNotIn("n9", line.split())
            self.assertIn("removed cyberlab-a", out)
            self.assertIn("removed cyberlab-ab", out)
            self.assertIn("PASS nuke", out)
        self.each_bash(check)

    def test_nuke_images_only_left(self):
        def check(bash):
            self.fixture("F2")
            rc, out, err, log = self.cli(bash, ["nuke"])
            self.assertEqual(0, rc, err)
            self.assertIn("PASS nuke: nothing to remove", out)
            self.assertFalse(any(l.startswith("image rm") for l in log), log)
            self.fixture("F2")
            rc, out, err, log = self.cli(bash, ["nuke", "--images"])
            self.assertEqual(0, rc, err)
            self.assertIn("image rm -f i1 i2", log)
            self.assertIn("image rm -f i3", log)
            for line in self.rm_lines(log):
                self.assertNotIn("i9", line.split())
        self.each_bash(check)

    def test_nuke_nothing(self):
        def check(bash):
            self.fixture("F0")
            rc, out, err, log = self.cli(bash, ["nuke", "--images"])
            self.assertEqual(0, rc, err)
            self.assertEqual("PASS nuke: nothing to remove\n", out)
        self.each_bash(check)

    def test_help_lists_image_options(self):
        def check(bash):
            self.fixture("F0")
            rc, out, err, log = self.cli(bash, ["--help"])
            self.assertEqual(0, rc, err)
            self.assertIn("down <lab> [--images]", out)
            self.assertIn("nuke [--images]", out)
        self.each_bash(check)


if __name__ == "__main__":
    unittest.main()
