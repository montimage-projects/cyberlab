"""Fake-WAN pools in the lab isolation policy (skills/cyberlab/scripts/lab_policy.py), issue #20.

Run from the repo root: python3 -m unittest discover -s tests
Each case feeds a resolved compose model (the shape `docker compose config --format json` prints,
taken from a real lab) to the script and checks its exit code and FAIL lines."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "cyberlab", "scripts", "lab_policy.py")
INHIBIT = "com.docker.network.bridge.inhibit_ipv4"

BASE = {
    "name": "cyberlab-t",
    "networks": {"lab": {"name": "cyberlab-t_lab", "driver": "bridge", "internal": True,
                         "driver_opts": {INHIBIT: "true"}}},
    "services": {
        "victim": {"image": "nginx:1.27-alpine", "networks": {"lab": None}},
        "generator": {"image": "python:3.12-slim", "networks": {"lab": None}},
    },
}


def lab(ipam=None, victim=None, generator=None, **net):
    """BASE with the lab network's ipam and extra keys, and each service's network options."""
    cfg = copy.deepcopy(BASE)
    if ipam is not None:
        cfg["networks"]["lab"]["ipam"] = ipam
    cfg["networks"]["lab"].update(net)
    if victim is not None:
        cfg["services"]["victim"]["networks"] = {"lab": victim}
    if generator is not None:
        cfg["services"]["generator"]["networks"] = {"lab": generator}
    return cfg


def pool(**kw):
    return {"config": [kw]}


def check(cfg):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
    try:
        p = subprocess.run([sys.executable, SCRIPT, "--lab-dir", "/abs/lab", "--config", f.name],
                           capture_output=True, text=True)
    finally:
        os.unlink(f.name)
    return p.returncode, p.stdout + p.stderr


class Accepted(unittest.TestCase):
    def assertPass(self, cfg):
        rc, out = check(cfg)
        self.assertEqual(rc, 0, out)
        self.assertIn("RESULT PASS", out)
        return out

    def test_lab_without_ipam_still_passes(self):
        out = self.assertPass(lab())
        self.assertIn("PASS network lab internal", out)

    def test_testnet_pool_with_pinned_addresses(self):
        out = self.assertPass(lab(pool(subnet="203.0.113.0/24"),
                                  victim={"ipv4_address": "203.0.113.10"}, generator={"ipv4_address": "203.0.113.32"}))
        self.assertIn("fake-WAN subnet 203.0.113.0/24", out)

    def test_every_testnet_range_and_a_narrower_pool(self):
        for subnet in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.32/29"):
            with self.subTest(subnet=subnet):
                self.assertPass(lab(pool(subnet=subnet)))

    def test_default_driver_gateway_and_ip_range(self):
        self.assertPass(lab({"driver": "default", "config": [
            {"subnet": "203.0.113.0/24", "gateway": "203.0.113.254", "ip_range": "203.0.113.128/25"}]},
            generator={"ipv4_address": "203.0.113.1"}))

    def test_pool_with_only_some_services_pinned(self):
        self.assertPass(lab(pool(subnet="198.51.100.0/24"), generator={"ipv4_address": "198.51.100.7", "aliases": ["c2"]}))


class Rejected(unittest.TestCase):
    def assertFail(self, cfg, *needles):
        rc, out = check(cfg)
        self.assertEqual(rc, 2, out)
        self.assertIn("RESULT FAIL", out)
        for n in needles:
            self.assertIn(n, out)
        return out

    def test_public_and_private_subnets(self):
        for subnet in ("66.179.31.0/24", "1.1.1.0/24", "10.0.0.0/24", "172.30.0.0/16", "192.168.56.0/24"):
            with self.subTest(subnet=subnet):
                self.assertFail(lab(pool(subnet=subnet)), "outside the TEST-NET ranges")

    def test_host_critical_ranges(self):
        for subnet in ("127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "0.0.0.0/8", "240.0.0.0/4"):
            with self.subTest(subnet=subnet):
                self.assertFail(lab(pool(subnet=subnet)), "outside the TEST-NET ranges")

    def test_pool_wider_than_a_testnet_range(self):
        self.assertFail(lab(pool(subnet="203.0.112.0/23")), "outside the TEST-NET ranges")

    def test_host_bits_and_garbage_subnets(self):
        for subnet in ("203.0.113.5/24", "not-a-net", ""):
            with self.subTest(subnet=subnet):
                self.assertFail(lab(pool(subnet=subnet)), "is not a network address")

    def test_ipv6_pool(self):
        self.assertFail(lab(pool(subnet="2001:db8::/64")), "outside the TEST-NET ranges")

    def test_ipam_driver_options_and_extra_keys(self):
        self.assertFail(lab({"driver": "dhcp", "config": [{"subnet": "203.0.113.0/24"}]}), "ipam driver dhcp")
        self.assertFail(lab({"config": [{"subnet": "203.0.113.0/24"}], "options": {"x": "y"}}), "ipam key(s) ['options']")
        self.assertFail(lab(pool(subnet="203.0.113.0/24", aux_addresses={"h": "203.0.113.9"})),
                        "ipam config key(s) ['aux_addresses']")

    def test_zero_or_several_pools(self):
        self.assertFail(lab({"config": []}), "exactly one config entry")
        self.assertFail(lab({"config": [{"subnet": "203.0.113.0/24"}, {"subnet": "198.51.100.0/24"}]}),
                        "exactly one config entry")

    def test_gateway_and_ip_range_outside_the_subnet(self):
        self.assertFail(lab(pool(subnet="203.0.113.0/24", gateway="198.51.100.1")), "ipam gateway 198.51.100.1 is outside")
        self.assertFail(lab(pool(subnet="203.0.113.0/25", ip_range="203.0.113.128/25")), "ipam ip_range 203.0.113.128/25 is outside")

    def test_pinned_address_outside_its_pool(self):
        self.assertFail(lab(pool(subnet="203.0.113.0/24"), generator={"ipv4_address": "66.179.31.32"}),
                        "service generator", "not a usable host address of 203.0.113.0/24")

    def test_pinned_network_or_broadcast_address(self):
        for addr in ("203.0.113.0", "203.0.113.255"):
            with self.subTest(addr=addr):
                self.assertFail(lab(pool(subnet="203.0.113.0/24"), generator={"ipv4_address": addr}),
                                "not a usable host address")

    def test_pinned_address_without_a_pool(self):
        self.assertFail(lab(generator={"ipv4_address": "203.0.113.32"}), "has no valid fake-WAN ipam subnet")

    def test_isolation_is_not_relaxed_by_a_pool(self):
        """A valid fake-WAN pool never excuses a network that is not internal or keeps a host address."""
        self.assertFail(lab(pool(subnet="203.0.113.0/24"), internal=False), "internal is not true")
        self.assertFail(lab(pool(subnet="203.0.113.0/24"), driver_opts={}), f"{INHIBIT} is not \"true\"")


if __name__ == "__main__":
    unittest.main()
