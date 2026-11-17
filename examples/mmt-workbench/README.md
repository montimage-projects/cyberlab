# Example consumer: MMT workbench

Not part of the cyberlab skill. This is how a consumer (the MMT rule and plugin generator skills) can bring its own tools **outside** the lab and replay cyberlab traces with them.

- `Dockerfile` — Ubuntu 24.04 (pinned digest) with mmt-dpi v1.10.2 from its GitHub Release (SHA256SUMS chain-checked by `fetch_mmt_dpi.sh`), mmt-security built from commit `a78a4fd`, the `mmt-plugin` CLI from commit `7ec9cd9`, plus tshark, valgrind and a private SDK prefix at `/sdk/mmt`. Builds natively on arm64 and amd64.
- `detect.sh` — inside that image: compile XML rules (or load the installed ones), optionally add an mmt-dpi plugin through `MMT_DPI_PLUGINS_DIR`, replay pcaps through `mmt_sec_standalone` and count alerts per rule.

```bash
docker build -t mmt/workbench:local examples/mmt-workbench
docker run --rm --network none -v "$PWD/examples/mmt-workbench:/x:ro" -v <lab>/out:/in:ro -v "$PWD/det:/out" \
  mmt/workbench:local /x/detect.sh --out /out --rule /in/<rule>.xml /in/attack.pcap /in/benign.pcap
```

Validated on 2026-11-17: an mmt-security FTP brute-force rule gave 5 alerts on a cyberlab `ftp-bruteforce` attack trace and 0 on the benign trace; the rule-generator's `test_rule.sh` (rule 231, `--valgrind`) and the plugin generator's evals (4/4 with the SDK) passed in this image.
