#!/usr/bin/env bash
# fake docker for tests/test_cyberlab_cli.py: never talks to a real daemon. Every call is logged to
# $STUB_DIR/log (one argv per line) and answered from fixture files in $STUB_DIR:
#   containers : <id> <name> <project>      networks : <id> <name> <project>
#   volumes    : <name> <project>           images   : <id> <name|-> <project|->
# ("-" as name = untagged; "-" as project = an image with no compose project label, e.g. a pulled
# image or the tools image). A missing file means "none". `compose down --rmi` and `image rm`
# rewrite the images file, so a test can assert what is left.
# `image ls` behaves like Docker 29+: untagged records (name "-") are listed only when the args
# include -a, --all or a short-flag cluster containing a (e.g. -aq); a key-only
# `--filter label=com.docker.compose.project` keeps only records whose project is not "-";
# `--filter label=com.docker.compose.project=<p>` keeps only that project's records; no label
# filter lists everything subject to the -a rule. `image inspect -f` prints an empty project for
# records whose project is "-".
# Env switches:
#   STUB_PROJECT (default cyberlab-a): the project `compose config` reports; `compose down --rmi`
#     deletes only this project's TAGGED image records (name != "-"), keeping untagged ones — the
#     behaviour of Compose before v5.5.1, which left a rebuild's superseded images behind.
#   STUB_DOWN_RC (default 0): exit code of `compose down`; non-zero leaves the images file untouched.
#   STUB_IMAGE_RM_FAILS=1: `image rm` exits 1 without removing anything.
#   STUB_NO_TOOLS=1: `image inspect <ref>` without -f (the CLI's tools-image check) exits 1.
#   CYBERLAB_TOOLS (default cyberlab/tools:local): the image `run` shifts to before exec'ing the rest.
printf '%s\n' "$*" >> "$STUB_DIR/log"
fx() { [ -f "$STUB_DIR/$1" ] && cat "$STUB_DIR/$1"; }
proj_filter() { local a p=""; for a in "$@"; do case "$a" in label=com.docker.compose.project=*) p="${a#label=com.docker.compose.project=}";; esac; done; printf '%s' "$p"; }
has() { local n="$1" a; shift; for a in "$@"; do [ "$a" = "$n" ] && return 0; done; return 1; }
fmt_of() { local prev="" a; for a in "$@"; do [ "$prev" = "--format" ] && { printf '%s' "$a"; return; }; prev="$a"; done; }
rmi_of_project() { # delete project $1's tagged image records, keep the untagged ("-") ones
  [ -f "$STUB_DIR/images" ] || return 0
  awk -v p="$1" '!($3 == p && $2 != "-")' "$STUB_DIR/images" > "$STUB_DIR/images.tmp" && mv "$STUB_DIR/images.tmp" "$STUB_DIR/images"
}
drop_image() { # delete image record $1 (by id) from the images fixture
  [ -f "$STUB_DIR/images" ] || return 0
  awk -v id="$1" '$1 != id' "$STUB_DIR/images" > "$STUB_DIR/images.tmp" && mv "$STUB_DIR/images.tmp" "$STUB_DIR/images"
}
case "$1" in
  info) exit 0;;
  version) echo "0.0-stub"; exit 0;;
  compose)
    case "$2" in
      version) echo "stub"; exit 0;;
      config) printf '{"name": "%s"}' "${STUB_PROJECT:-cyberlab-a}"; exit 0;;
      down)
        if [ "${STUB_DOWN_RC:-0}" != 0 ]; then exit "$STUB_DOWN_RC"; fi
        if has --rmi "$@"; then
          rmi_of_project "${STUB_PROJECT:-cyberlab-a}"
        fi
        exit 0;;
      *) exit 0;;
    esac;;
  ps)
    p="$(proj_filter "$@")"
    if has -aq "$@"; then fx containers | awk -v p="$p" '$3==p{print $1}'
    else f="$(fmt_of "$@")"; case "$f" in container*) fx containers | awk '{print "container", $2, $3}';; *) fx containers | awk '{print $3}';; esac; fi;;
  network)
    case "$2" in
      ls) p="$(proj_filter "$@")"
          if has -q "$@"; then fx networks | awk -v p="$p" '$3==p{print $1}'
          else f="$(fmt_of "$@")"; case "$f" in network*) fx networks | awk '{print "network", $2, $3}';; *) fx networks | awk '{print $3}';; esac; fi;;
      *) exit 0;;
    esac;;
  volume)
    case "$2" in
      ls) p="$(proj_filter "$@")"
          if has -q "$@"; then fx volumes | awk -v p="$p" '$2==p{print $1}'
          else f="$(fmt_of "$@")"; case "$f" in volume*) fx volumes | awk '{print "volume", $1, $2}';; *) fx volumes | awk '{print $2}';; esac; fi;;
      *) exit 0;;
    esac;;
  image)
    case "$2" in
      ls) p="$(proj_filter "$@")"
          a=0; for arg in "$@"; do case "$arg" in --all) a=1;; --*) ;; -*a*) a=1;; esac; done
          kf=0; has label=com.docker.compose.project "$@" && kf=1
          fx images | awk -v p="$p" -v a="$a" -v kf="$kf" \
            '($2 != "-" || a) && (p != "" ? $3 == p : (kf ? $3 != "-" : 1)) {print $1}';;
      inspect)
          if has -f "$@"; then
            shift 2; [ "$1" = "-f" ] && shift 2
            for id in "$@"; do fx images | awk -v id="$id" '$1==id{print "image", ($2=="-" ? "sha256:" $1 : $2), ($3=="-" ? "" : $3)}'; done
          elif [ "${STUB_NO_TOOLS:-0}" = 1 ]; then exit 1
          else exit 0; fi;;
      rm)
          if [ "${STUB_IMAGE_RM_FAILS:-0}" = 1 ]; then exit 1; fi
          shift 2; [ "${1:-}" = "-f" ] && shift
          for id in "$@"; do drop_image "$id"; done
          exit 0;;
      *) exit 0;;
    esac;;
  run)
    while [ $# -gt 0 ] && [ "$1" != "${CYBERLAB_TOOLS:-cyberlab/tools:local}" ]; do shift; done
    shift; exec "$@";;
  *) exit 0;;
esac
