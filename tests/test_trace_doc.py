"""Who is who in trace documents (skills/cyberlab/scripts/trace_doc.py), on synthetic frames.

Run from the repo root: python3 -m unittest discover -s tests
The frames go through frame_rows() with tshark replaced by canned output, so the MAC-to-IP folding of
non-IP frames (ARP) is the one the real documents get."""
import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "cyberlab", "scripts"))
import trace_doc

VIC_MAC, ATK_MAC, GW_MAC, BCAST = "02:00:0a:00:00:01", "02:00:0a:00:00:02", "02:00:0a:00:00:fe", "ff:ff:ff:ff:ff:ff"
VIC_IP, ATK_IP, GW_IP = "192.168.56.1", "192.168.56.2", "192.168.56.254"
SCRATCH = "The trace is crafted: the generator wrote these addresses, and no host or network was involved."


def arp(esrc, edst, info="ARP"):
    return (esrc, edst, "", "", "ARP", info)


def icmp(esrc, edst, src, dst):
    return (esrc, edst, src, dst, "ICMP", "Echo (ping) request")


def rows_of(frames):
    """frame_rows() over tshark output listing these frames: (eth.src, eth.dst, ip.src, ip.dst, proto, info)."""
    lines = []
    for i, (esrc, edst, s4, d4, proto, info) in enumerate(frames, 1):
        ip = [s4, d4, "", ""] if ":" not in s4 else ["", "", s4, d4]   # ip.src/dst, else ipv6.src/dst
        lines.append("\t".join([str(i), f"{i * 0.1:.3f}", "60", esrc, edst, *ip, "", "", proto, info]))
    with mock.patch.object(trace_doc, "run", return_value=(0, "\n".join(lines) + "\n", "")):
        return trace_doc.frame_rows("x.pcap")


def mission():
    return {"goal": "", "fields": {}, "traces": {}, "log": []}


def mech(trace, *roles):
    return {"roles": {trace: list(roles)}}


def role_of(who, addr):
    return next(e["role"] for e in who["rows"] if e["addr"] == addr)


# An ARP spoof: the attacker (no IP frames) tells the victim the gateway is at its MAC; the victim pings once.
SPOOF = [arp(VIC_MAC, BCAST, f"Who has {GW_IP}?"), arp(ATK_MAC, VIC_MAC, f"{GW_IP} is at {ATK_MAC}"),
         arp(ATK_MAC, VIC_MAC, f"{GW_IP} is at {ATK_MAC}"), icmp(VIC_MAC, ATK_MAC, VIC_IP, GW_IP)]
CRAFTED = {"origin": "crafted (synthetic)", "generator": "python3 spoof.py"}
CRAFT_PCAP = {"origin": "crafted (synthetic)", "generator": "craft_pcap.py icmp"}


class MacRolesTarget(unittest.TestCase):
    """#17: a Roles: line may name a host by MAC."""

    def who(self, frames, *roles, prov=CRAFTED):
        return trace_doc.who_is_who("attack.pcap", prov, mech("attack.pcap", *roles), mission(), rows_of(frames))

    def test_mac_of_host_that_also_sends_ip_resolves(self):
        who = self.who(SPOOF, ("Victim", VIC_MAC), ("Attacker", ATK_MAC))
        self.assertEqual(who["unresolved"], [])
        self.assertEqual(role_of(who, VIC_IP), "Victim")
        self.assertEqual(next(e["mac"] for e in who["rows"] if e["addr"] == VIC_IP), VIC_MAC)

    def test_mac_target_is_case_insensitive(self):
        who = self.who(SPOOF, ("Victim", VIC_MAC.upper()))
        self.assertEqual(who["unresolved"], [])
        self.assertEqual(role_of(who, VIC_IP), "Victim")

    def test_mac_of_host_that_sends_only_non_ip_frames_still_resolves(self):
        who = self.who(SPOOF, ("Attacker", ATK_MAC))
        self.assertEqual(who["unresolved"], [])
        self.assertEqual(role_of(who, ATK_MAC), "Attacker")

    def test_mac_absent_from_the_trace_still_warns(self):
        who = self.who(SPOOF, ("Victim", "02:00:0a:00:00:99"))
        self.assertEqual([u[:2] for u in who["unresolved"]], [("Victim", "02:00:0a:00:00:99")])
        with tempfile.TemporaryDirectory() as lab:
            os.mkdir(os.path.join(lab, "out"))
            w = trace_doc.doc_warnings(lab, "attack.pcap", mission(), {"found": False}, {}, who)
        self.assertIn("`Roles: Victim = 02:00:0a:00:00:99` in mechanism.md matches no address in the trace", w)

    def test_mac_that_sends_for_several_addresses_is_not_guessed(self):
        # MITM: the attacker forwards one of the victim's packets before sending its own
        frames = SPOOF + [icmp(ATK_MAC, GW_MAC, VIC_IP, GW_IP), icmp(ATK_MAC, GW_MAC, ATK_IP, GW_IP)]
        who = self.who(frames, ("Attacker", ATK_MAC))
        self.assertEqual([u[:2] for u in who["unresolved"]], [("Attacker", ATK_MAC)])
        self.assertNotIn("Attacker", [e["role"] for e in who["rows"]])
        with tempfile.TemporaryDirectory() as lab:
            os.mkdir(os.path.join(lab, "out"))
            w = trace_doc.doc_warnings(lab, "attack.pcap", mission(), {"found": False}, {}, who)
        line = next(x for x in w if x.startswith(f"`Roles: Attacker = {ATK_MAC}`"))
        self.assertIn("matches no address in the trace", line)
        self.assertIn(VIC_IP, line)
        self.assertIn(ATK_IP, line)

    def test_mac_whose_address_another_mac_also_sent_is_not_guessed(self):
        # the attacker forwards only the victim's packets: the victim's IP comes from two MACs
        frames = SPOOF + [icmp(ATK_MAC, GW_MAC, VIC_IP, GW_IP)]
        who = self.who(frames, ("Victim", VIC_MAC))
        self.assertEqual([u[:2] for u in who["unresolved"]], [("Victim", VIC_MAC)])
        self.assertNotIn("Victim", [e["role"] for e in who["rows"]])
        with tempfile.TemporaryDirectory() as lab:
            os.mkdir(os.path.join(lab, "out"))
            w = trace_doc.doc_warnings(lab, "attack.pcap", mission(), {"found": False}, {}, who)
        self.assertIn(f"`Roles: Victim = {VIC_MAC}` in mechanism.md matches no address in the trace: "
                      f"{VIC_IP}, which MAC {VIC_MAC} sent from, also came from MAC {ATK_MAC}; "
                      "name the host by its IP address", w)

    def test_mac_that_sent_ip_only_from_unspecified_address_warns_plainly(self):
        frames = [icmp(GW_MAC, BCAST, "0.0.0.0", "255.255.255.255")] + SPOOF
        who = self.who(frames, ("Gateway", GW_MAC))
        self.assertEqual(who["unresolved"], [("Gateway", GW_MAC, "")])

    def test_dual_stack_host_gets_the_role_on_both_addresses(self):
        frames = SPOOF + [(VIC_MAC, ATK_MAC, "fd00::1", "fd00::2", "ICMPv6", "Echo (ping) request")]
        who = self.who(frames, ("Victim", VIC_MAC))
        self.assertEqual(who["unresolved"], [])
        self.assertEqual((role_of(who, VIC_IP), role_of(who, "fd00::1")), ("Victim", "Victim"))

    def test_unspecified_source_does_not_make_a_mac_ambiguous(self):
        frames = [icmp(VIC_MAC, BCAST, "0.0.0.0", "255.255.255.255")] + SPOOF
        who = self.who(frames, ("Victim", VIC_MAC))
        self.assertEqual(who["unresolved"], [])
        self.assertEqual(role_of(who, VIC_IP), "Victim")


class FakeWanAddresses(unittest.TestCase):
    """Pinned (fake-WAN) addresses and the brief's Stand-ins line, issue #20."""

    def test_stand_ins_line_is_read_from_the_brief(self):
        with tempfile.TemporaryDirectory() as lab:
            with open(os.path.join(lab, "mission.md"), "w") as f:
                f.write("# Mission: x\n- Server/client: nginx\n- Stand-ins: 203.0.113.32 = IoC 66.179.31.32\n")
            fields = trace_doc.read_mission(lab)["fields"]
        self.assertEqual(fields["Stand-ins"], "203.0.113.32 = IoC 66.179.31.32")
        self.assertEqual(fields["Server/client"], "nginx")

    def test_pinned_addresses_come_from_provenance_services(self):
        prov = {"services": {"generator": {"ipv4_address": "203.0.113.32"}, "victim": {"ipv4_address": ["203.0.113.10"]},
                             "capture": {"network_mode": "service:victim"}}}
        self.assertEqual(trace_doc.pinned_addresses(prov), {"203.0.113.32": "generator", "203.0.113.10": "victim"})
        self.assertIn("pinned in `docker-compose.yml`", trace_doc.addresses_note(trace_doc.pinned_addresses(prov)))

    def test_pinned_of_reads_the_resolved_compose_service(self):
        self.assertEqual(trace_doc.pinned_of({"networks": {"lab": {"ipv4_address": "203.0.113.32"}}}), "203.0.113.32")
        self.assertEqual(trace_doc.pinned_of({"networks": {"b": {"ipv4_address": "198.51.100.2"}, "a": {"ipv4_address": "192.0.2.9"}}}),
                         ["192.0.2.9", "198.51.100.2"])
        for svc in ({"networks": {"lab": None}}, {"networks": {"lab": {"aliases": ["x"]}}}, {"network_mode": "service:victim"}):
            with self.subTest(svc=svc):
                self.assertIsNone(trace_doc.pinned_of(svc))
        prov = {"services": {"generator": {"ipv4_address": trace_doc.pinned_of(
            {"networks": {"b": {"ipv4_address": "198.51.100.2"}, "a": {"ipv4_address": "192.0.2.9"}}})}}}
        self.assertEqual(trace_doc.pinned_addresses(prov), {"192.0.2.9": "generator", "198.51.100.2": "generator"})

    def test_unpinned_lab_keeps_the_docker_assigns_note(self):
        self.assertEqual(trace_doc.addresses_note(trace_doc.pinned_addresses({"services": {"generator": {}}})),
                         "Docker assigns the addresses on each run.")


class DerivedTrace(unittest.TestCase):
    """#16: a --script trace derived from another lab trace does not claim no host was involved."""

    FRAMES = (icmp(VIC_MAC, ATK_MAC, VIC_IP, ATK_IP), icmp(ATK_MAC, VIC_MAC, ATK_IP, VIC_IP),
              icmp(GW_MAC, VIC_MAC, GW_IP, VIC_IP))

    def lab(self, source_origin=None):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.mkdir(os.path.join(d, "out"))
        if source_origin:
            with open(os.path.join(d, "out", "benign.provenance.json"), "w") as f:
                json.dump({"origin": source_origin}, f)
        return d

    def who(self, prov, lab=""):
        roles = (("Attacker", ATK_IP), ("Victim", VIC_IP))
        return trace_doc.who_is_who("attack.pcap", prov, mech("attack.pcap", *roles), mission(), rows_of(self.FRAMES), lab=lab)

    def derived(self):
        return {"origin": "crafted (synthetic)", "generator": "python3 derive.py",
                "lab_traces_at_generation": {"benign.pcap": "0" * 64}}

    def test_derived_trace_names_its_source(self):
        who = self.who(self.derived(), self.lab("lab capture"))
        text = "\n".join(trace_doc.who_section(who))
        self.assertIn("derived from `benign.pcap` (a lab capture)", text)
        self.assertIn("`derive.py`", text)
        self.assertNotIn("no host or network was involved", text)
        self.assertNotIn("no network used", text)
        self.assertNotIn("crafted address", text)
        self.assertIn('subgraph net["derived from benign.pcap by derive.py: addresses from there"]', text)
        self.assertEqual(role_of(who, GW_IP), "Other (from benign.pcap or added by derive.py)")

    def test_source_without_provenance_is_not_called_a_lab_capture(self):
        text = "\n".join(trace_doc.who_section(self.who(self.derived(), self.lab())))
        self.assertIn("derived from `benign.pcap`:", text)
        self.assertNotIn("lab capture", text)
        self.assertNotIn("no host or network was involved", text)

    def test_source_that_is_itself_crafted(self):
        text = "\n".join(trace_doc.who_section(self.who(self.derived(), self.lab("crafted (synthetic)"))))
        self.assertIn("derived from `benign.pcap` (a crafted trace)", text)

    def test_several_sources_are_all_named(self):
        prov = self.derived()
        prov["lab_traces_at_generation"]["attack-a.pcap"] = "1" * 64
        text = "\n".join(trace_doc.who_section(self.who(prov, self.lab("lab capture"))))
        self.assertIn("`attack-a.pcap`", text)
        self.assertIn("`benign.pcap` (a lab capture)", text)
        self.assertIn("those traces'", text)

    def test_trace_from_scratch_keeps_the_sentence(self):
        for prov in (CRAFT_PCAP, CRAFTED):
            who = self.who(prov, self.lab("lab capture"))
            lines = trace_doc.who_section(who)
            self.assertIn(SCRATCH, lines[2])
            self.assertIn("crafted trace: addresses written by the generator, no network used", "\n".join(lines))
            self.assertEqual(role_of(who, GW_IP), "Other (crafted address)")

    def test_only_traces_the_script_names_are_sources(self):
        # an older cyberlab recorded every trace in out/; the script reads only benign.pcap
        lab = self.lab("lab capture")
        with open(os.path.join(lab, "derive.py"), "w") as f:
            f.write('SRC = "/lab/out/benign.pcap"\n')
        for n in ("benign.pcap", "attack-other.pcap"):
            open(os.path.join(lab, "out", n), "wb").close()
        prov = dict(self.derived(), command="cyberlab craft <lab> attack.pcap --script derive.py",
                    lab_traces_at_generation={"benign.pcap": "0" * 64, "attack-other.pcap": "1" * 64})
        text = "\n".join(trace_doc.who_section(self.who(prov, lab)))
        self.assertIn("derived from `benign.pcap` (a lab capture):", text)
        self.assertNotIn("attack-other.pcap", text)

    def test_who_is_who_without_lab_still_works(self):
        who = trace_doc.who_is_who("attack.pcap", self.derived(), {}, mission(), rows_of(self.FRAMES))
        self.assertIn("derived from `benign.pcap`", "\n".join(trace_doc.who_section(who)))


class DocumentVersion(unittest.TestCase):
    """#15: the header names the cyberlab that wrote the document; the summary table keeps the trace's version."""

    NOW = "2026-11-19T14:23:20Z"

    def lab(self, trace_version=None):
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d)
        os.mkdir(os.path.join(d, "out"))
        open(os.path.join(d, "out", "attack.pcap"), "wb").close()
        prov = {"origin": "crafted (synthetic)", "generator": "craft_pcap.py icmp"}
        if trace_version is not None:
            prov["cyberlab_version"] = trace_version
        with open(os.path.join(d, "out", "attack.provenance.json"), "w") as f:
            json.dump(prov, f)
        return d

    def render(self, lab, version):
        """The document's lines, with tshark and capinfos answering nothing."""
        with mock.patch.object(trace_doc, "run", return_value=(0, "", "")):
            return trace_doc.render(lab, "attack.pcap", mission(), {}, {}, self.NOW, "lab", {}, [],
                                    doc_version=version).split("\n")

    def header(self, lines):
        return next(l for l in lines if l.startswith("<!--"))

    def cyberlab_row(self, lines):
        return next(l for l in lines if l.startswith("| cyberlab |"))

    def test_header_names_the_version_that_wrote_the_document(self):
        lines = self.render(self.lab("1.2.0"), "1.3.0")
        self.assertEqual(self.header(lines), f"<!-- Written by cyberlab 1.3.0 on {self.NOW}; "
                                             "regenerate with: cyberlab doc <lab> attack.pcap -->")
        self.assertNotIn("1.2.0", self.header(lines))

    def test_table_keeps_the_trace_version_and_names_the_writer_when_they_differ(self):
        lines = self.render(self.lab("1.2.0"), "1.3.0")
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | 1.2.0 (document written by 1.3.0) |")

    def test_same_version_reads_as_before_apart_from_the_header(self):
        lines = self.render(self.lab("1.3.0"), "1.3.0")
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | 1.3.0 |")
        self.assertIn("Written by cyberlab 1.3.0 on", self.header(lines))
        self.assertNotIn("document written by", "\n".join(lines))

    def test_unknown_writer_version_leaves_no_gap_and_no_suffix(self):
        lines = self.render(self.lab("1.2.0"), "")
        self.assertEqual(self.header(lines), f"<!-- Written by cyberlab on {self.NOW}; "
                                             "regenerate with: cyberlab doc <lab> attack.pcap -->")
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | 1.2.0 |")

    def test_trace_without_recorded_version_still_names_the_writer(self):
        lines = self.render(self.lab(), "1.3.0")
        self.assertIn("Written by cyberlab 1.3.0 on", self.header(lines))
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | unrecorded (generated before trace documents "
                                                   "existed; document written by 1.3.0) |")
        lines = self.render(self.lab(""), "1.3.0")
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | unrecorded (document written by 1.3.0) |")
        lines = self.render(self.lab(), "")
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | unrecorded (generated before trace documents existed) |")

    def test_doc_command_passes_its_version_to_the_document(self):
        lab = self.lab("1.2.0")
        argv = ["trace_doc.py", "doc", "--lab", lab, "--version", "1.3.0"]
        with mock.patch.object(sys, "argv", argv), mock.patch.object(trace_doc, "run", return_value=(0, "", "")), \
                mock.patch("sys.stdout"), self.assertRaises(SystemExit) as done:
            trace_doc.main()
        self.assertEqual(done.exception.code, 0)
        with open(os.path.join(lab, "out", "attack.md")) as f:
            lines = f.read().split("\n")
        self.assertIn("Written by cyberlab 1.3.0 on", self.header(lines))
        self.assertEqual(self.cyberlab_row(lines), "| cyberlab | 1.2.0 (document written by 1.3.0) |")

    def test_cyberlab_passes_the_skill_version_to_every_doc_call(self):
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "skills", "cyberlab", "scripts", "cyberlab")
        with open(script) as f:
            calls = [l for l in f if "trace_doc.py doc " in l]
        self.assertEqual(len(calls), 2)
        for line in calls:
            self.assertIn('--version "$(skill_version)"', line)


if __name__ == "__main__":
    unittest.main()
