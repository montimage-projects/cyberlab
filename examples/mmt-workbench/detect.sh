#!/usr/bin/env bash
# Replay pcaps through mmt-security and count alerts per rule. Runs INSIDE the workbench
# (`cyberlab detect` calls it); on the host it stops with an error.
#
# Usage: detect.sh --out <dir> [--rule <file.xml>]... [--plugin <mmtp_x.so>]... <pcap>...
#   --rule    compile this XML rule (compile_rule, -Werror) and load only the --rule rules;
#             without --rule, every rule installed in /opt/mmt/security/rules is loaded
#   --plugin  add an mmt-dpi protocol plugin (from mmt-plugin build) to the SDK's plugins,
#             through MMT_DPI_PLUGINS_DIR, so rules can use the plugin's attributes
#   --out     directory for <pcap>/mmt-security*.csv, <pcap>.log and summary.tsv
# Output: one line per pcap and rule id, `ALERTS <pcap> rule <id> <count>`, then
#         `RESULT PASS` (every replay exited 0) or `RESULT FAIL`.
# Exit: 0 replays ran, 1 usage/environment error, 2 a rule failed to compile or a replay crashed.
set -u
die() { echo "Error: $*" >&2; exit 1; }
case "${1:-}" in -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,"");print;next} NR>1{exit}' "$0"; exit 0;; esac
SRC=/usr/src/mmt-security
[ -x "$SRC/mmt_sec_standalone" ] || die "mmt_sec_standalone not found in $SRC: run this through 'cyberlab detect' (workbench image), not on the host."
OUT="" ; RULES=() ; PLUGINS=() ; PCAPS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="$2"; shift 2;;
    --rule) RULES+=("$2"); shift 2;;
    --plugin) PLUGINS+=("$2"); shift 2;;
    -*) die "unknown option '$1'. Run '$0 --help'.";;
    *) PCAPS+=("$1"); shift;;
  esac
done
[ -n "$OUT" ] || die "missing --out <dir>."
[ ${#PCAPS[@]} -gt 0 ] || die "no pcap given. Example: $0 --out /out attack.pcap benign.pcap"
for f in ${PCAPS[@]+"${PCAPS[@]}"} ${RULES[@]+"${RULES[@]}"} ${PLUGINS[@]+"${PLUGINS[@]}"}; do
  [ -f "$f" ] || die "file not found: $f"
done
mkdir -p "$OUT" || die "cannot create $OUT"
RUN="$(mktemp -d /tmp/cyberlab-detect.XXXXXX)"; trap 'rm -rf "$RUN"' EXIT
mkdir -p "$RUN/rules"

if [ ${#RULES[@]} -gt 0 ]; then
  for x in "${RULES[@]}"; do
    so="$RUN/rules/$(basename "$x" .xml).so"
    ( cd "$RUN" && "$SRC/compile_rule" "$so" "$x" "-Werror" ) >"$RUN/compile.log" 2>&1
    if [ ! -f "$so" ] || grep -qE 'ERROR_SEC|HALT_SEC|warning:|error:' "$RUN/compile.log"; then
      echo "FAIL compile $(basename "$x"):"; sed -n '1,30p' "$RUN/compile.log"; exit 2
    fi
    echo "PASS compile $(basename "$x")"
  done
else
  ln -s /opt/mmt/security/rules/*.so "$RUN/rules/" 2>/dev/null || die "no installed rules in /opt/mmt/security/rules."
  echo "NOTE rules   all $(ls "$RUN/rules" | wc -l) installed sample rules loaded"
fi

if [ ${#PLUGINS[@]} -gt 0 ]; then
  mkdir -p "$RUN/plugins"
  ln -s /opt/mmt/plugins/*.so "$RUN/plugins/"
  for p in "${PLUGINS[@]}"; do cp "$p" "$RUN/plugins/"; echo "NOTE plugin  $(basename "$p") loaded"; done
  export MMT_DPI_PLUGINS_DIR="$RUN/plugins"
fi

printf 'pcap\trule\talerts\n' > "$OUT/summary.tsv"
FAILED=0
for p in "${PCAPS[@]}"; do
  b="$(basename "$p")"; b="${b%.*}"
  rm -rf "${OUT:?}/$b"; mkdir -p "$OUT/$b"
  ( cd "$RUN" && "$SRC/mmt_sec_standalone" -t "$p" -f "$OUT/$b/" ) >"$OUT/$b.log" 2>&1
  rc=$?
  if [ "$rc" != 0 ]; then
    echo "FAIL replay $b exit=$rc (log: $OUT/$b.log)"; tail -5 "$OUT/$b.log"; FAILED=1; continue
  fi
  counts="$(cat "$OUT/$b"/mmt-security*.csv 2>/dev/null | awk -F, 'NF>=5 {n[$5]++} END {for (r in n) print r, n[r]}' | sort -n)"
  if [ -z "$counts" ]; then
    echo "ALERTS $b none"; printf '%s\t-\t0\n' "$b" >> "$OUT/summary.tsv"
  else
    while read -r rid n; do
      echo "ALERTS $b rule $rid $n"; printf '%s\t%s\t%s\n' "$b" "$rid" "$n" >> "$OUT/summary.tsv"
    done <<< "$counts"
  fi
done
echo "summary: $OUT/summary.tsv"
[ "$FAILED" = 0 ] && { echo "RESULT PASS"; exit 0; } || { echo "RESULT FAIL"; exit 2; }
