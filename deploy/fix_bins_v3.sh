#!/bin/bash
# fix_bins_v3 — fetch/verify tunnel binaries via GitHub API (token), ELF-verified.
# Adaptive: logs full asset list when no pattern matches, so round-2 is instant.
# Run: nohup bash fix_bins_v3.sh >/dev/null 2>&1 &
set -u
BASE=/opt/multitunnel
BIN=$BASE/bin
LOG=$BASE/logs/bins_v3.log
TOKEN=$(cat /root/.ghtoken 2>/dev/null | tr -d '\r\n ')
WORK=/tmp/mtfbins
mkdir -p "$BIN" "$BASE/logs" "$WORK"
: > "$LOG"

log(){ echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG"; }
stage(){ python3 -c '
import json,sys,time
p="/opt/multitunnel/data/STATUS.json"
try: d=json.load(open(p))
except Exception: d={}
d.setdefault("stages",{})["bins_v3"]={"state":sys.argv[1],"ts":time.time()}
json.dump(d,open(p,"w"),indent=1)
' "$1" 2>/dev/null; }

gh(){ curl -sL --max-time 30 -H "Authorization: Bearer $TOKEN" -H "Accept: application/vnd.github+json" "$@"; }

is_elf(){ [ -f "$1" ] && [ "$(head -c 4 "$1" 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "7f454c46" ]; }

valid_bin(){ is_elf "$1" && [ "$(stat -c%s "$1" 2>/dev/null || echo 0)" -gt 1000000 ]; }

release_json(){
  local repo="$1"
  local j; j=$(gh "https://api.github.com/repos/$repo/releases/latest")
  if ! echo "$j" | jq -e '.tag_name' >/dev/null 2>&1; then
    j=$(gh "https://api.github.com/repos/$repo/releases?per_page=10" | jq -c '.[0] // empty')
  fi
  echo "$j"
}

install_file(){ # src dst
  cp -f "$1" "$2" && chmod +x "$2" && log "  installed $(stat -c%s "$2") bytes -> $2"
}

fetch_repo(){ # name repo pattern1;pattern2;...
  local name="$1" repo="$2" pats="$3"
  log "== [$name] $repo"
  local out="$BIN/$name"
  if valid_bin "$out"; then log "  already valid, skip"; return 0; fi
  local j tag; j=$(release_json "$repo")
  tag=$(echo "$j" | jq -r '.tag_name // empty' 2>/dev/null)
  if [ -z "$tag" ]; then log "  NO RELEASE FOUND for $repo"; echo "$j" | head -c 300 | tee -a "$LOG"; return 1; fi
  log "  release: $tag"
  # dump asset list (visibility for debugging)
  echo "$j" | jq -r '.assets[]? | "  asset: \(.name) \(.size)"' | tee -a "$LOG"
  local IFS=';'
  local url="" size=0
  for pat in $pats; do
    url=$(echo "$j" | jq -r --arg re "$pat" '.assets[]? | select(.name | test($re; "i")) | "\(.size)|\(.browser_download_url)"' | sort -t'|' -k1 -rn | head -1 | cut -d'|' -f2)
    [ -n "$url" ] && break
  done
  if [ -z "$url" ]; then log "  NO MATCHING ASSET (patterns: $pats)"; return 1; fi
  local fname="$WORK/$(basename "$url")"
  log "  downloading: $url"
  curl -sL --max-time 180 -H "Authorization: Bearer $TOKEN" -o "$fname" "$url" || { log "  download fail"; return 1; }
  log "  got $(stat -c%s "$fname") bytes"
  rm -rf "$WORK/x"; mkdir -p "$WORK/x"
  case "$fname" in
    *.zip) unzip -oq "$fname" -d "$WORK/x" 2>/dev/null || { log "  unzip fail"; return 1; } ;;
    *.tar.gz|*.tgz) tar xzf "$fname" -C "$WORK/x" 2>/dev/null || { log "  untar fail"; return 1; } ;;
    *.tar.xz) tar xJf "$fname" -C "$WORK/x" 2>/dev/null || { log "  untar.xz fail"; return 1; } ;;
    *.deb) (cd "$WORK/x" && ar x "$fname" 2>/dev/null && tar xf data.tar.* 2>/dev/null) || true ;;
    *) cp -f "$fname" "$WORK/x/$name" ;;
  esac
  local cand
  cand=$(find "$WORK/x" -type f 2>/dev/null | while read -r f; do is_elf "$f" && echo "$f" && break; done | head -1)
  if [ -z "$cand" ]; then
    # fall back: raw file itself might be the binary (already moved) or largest file
    cand="$WORK/x/$name"
    is_elf "$cand" || { log "  NO ELF FOUND after extract"; return 1; }
  fi
  install_file "$cand" "$out"
}

build_go(){ # name repo maindir
  local name="$1" repo="$2" maindir="$3"
  local out="$BIN/$name"
  if valid_bin "$out"; then log "== [$name] already valid, skip"; return 0; fi
  log "== [$name] BUILD FROM SOURCE $repo"
  if [ ! -x /opt/gotool/bin/go ]; then
    log "  downloading Go toolchain"
    curl -sL --max-time 300 -o "$WORK/go.tgz" https://go.dev/dl/go1.22.5.linux-amd64.tar.gz || { log "  go download fail"; return 1; }
    rm -rf /opt/gotool; mkdir -p /opt/gotool
    tar xzf "$WORK/go.tgz" -C /opt/gotool || { log "  go extract fail"; return 1; }
  fi
  rm -rf "$WORK/src"; mkdir -p "$WORK/src"
  gh -o "$WORK/src.tgz" "https://api.github.com/repos/$repo/tarball/HEAD" >/dev/null 2>&1
  tar xzf "$WORK/src.tgz" -C "$WORK/src" 2>/dev/null || { log "  src extract fail"; return 1; }
  local src; src=$(find "$WORK/src" -maxdepth 2 -name go.mod | head -1 | xargs dirname 2>/dev/null)
  [ -z "$src" ] && src=$(find "$WORK/src" -maxdepth 1 -type d | tail -1)
  log "  building in $src (main: $maindir)"
  (cd "$src" && GOFLAGS=-buildvcs=false CGO_ENABLED=0 /opt/gotool/bin/go build -trimpath -ldflags="-s -w" -o "$out" "./$maindir") || { log "  go build FAIL"; return 1; }
  is_elf "$out" && chmod +x "$out" && log "  built OK $(stat -c%s "$out") bytes" || return 1
}

stage running
log "===== bins_v3 start ====="

# --- release-based fetches (adaptive patterns, most specific first) ---
fetch_repo rathole   "rapiz1/rathole"              "^rathole-x86_64-unknown-linux-musl\.zip$;^rathole-x86_64-unknown-linux-gnu\.zip$;rathole.*x86_64.*(musl|gnu);rathole.*x86_64.*linux"
fetch_repo wstunnel  "erebe/wstunnel"              "wstunnel_.*_linux_amd64\.tar\.gz$;wstunnel_.*_linux_amd64;wstunnel.*linux.*amd64"
fetch_repo tuic      "EAimTY/tuic"                 "^tuic-x86_64-unknown-linux-musl$;^tuic-x86_64-unknown-linux-gnu$;tuic.*x86_64.*(musl|gnu);tuic.*linux.*x86_64"
fetch_repo waterwall "radkesvat/WaterWall"         "waterwall.*x86_64.*(musl|gnu|static).*(tar\.(gz|xz)|zip);waterwall.*x86_64.*linux;waterwall.*(x86_64|amd64)"
fetch_repo paqet     "hanselime/paqet"             "paqet.*linux.*(amd64|x86_64);paqet.*(amd64|x86_64);paqet.*linux"

# --- source-build fallbacks for personal repos without releases ---
if ! valid_bin "$BIN/hedioum"; then
  fetch_repo hedioum "DashSaman/Hedioum-Pool-Tunnel" "hedioum.*(linux|amd64|x86_64);hedioum" || true
  valid_bin "$BIN/hedioum" || build_go hedioum "DashSaman/Hedioum-Pool-Tunnel" "cmd/hedioum" || build_go hedioum "DashSaman/Hedioum-Pool-Tunnel" "./..."
fi

log "===== summary ====="
for f in rathole wstunnel tuic waterwall paqet hedioum; do
  if valid_bin "$BIN/$f"; then log "OK    $f"; else log "MISS  $f"; fi
done
n=$(for f in rathole wstunnel tuic waterwall paqet hedioum; do valid_bin "$BIN/$f" && echo x; done | wc -l)
stage "done: $n/6"
log "===== bins_v3 end ($n/6) ====="
