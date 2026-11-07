#!/usr/bin/env bash
# =============================================================================
#  fetch-bundle.sh  -  build the offline bundle for install-ejbca.sh
# =============================================================================
#  Run on an ONLINE Ubuntu 22.04 machine (same release as the targets), then
#  copy the resulting folder to the offline target.
#
#  USAGE
#    export GITHUB_TOKEN=<PAT with contents:read on ejbca-hsm-ejbca-patches and ejbca-hsm-ed25519>
#    ./fetch-bundle.sh --config FILE --out DIR
#
#    --config FILE   ejbca-install.conf - only the version keys are used here
#                    (JAVA_MAJOR, WILDFLY_VERSION, MARIADB_JDBC_VERSION,
#                     EJBCA_PATCHES_TAG, ED25519_VERSION, OS_PACKAGES)
#    --out DIR       bundle folder to create (must not exist or be empty)
#
#  Needs on this machine: curl, python3, sha256sum, apt-get, dpkg-scanpackages
#  (package dpkg-dev).
#
#  RESULT
#    DIR/install-ejbca.sh, DIR/ejbca-install.conf.sample   (from the EJBCA tag)
#    DIR/os/*.deb + Packages.gz                             (local apt repository)
#    DIR/wildfly/wildfly-<ver>.zip, mariadb-java-client-<ver>.jar
#    DIR/ejbca/ejbca-hsm-ejbca-patches-<tag>.tar.gz
#    DIR/addons/ed25519/*                                   (release assets + .sha256)
#    DIR/SHA256SUMS                                         (every file above)
#  The Utimaco PKCS#11 library is NOT part of the bundle (client-provided).
# =============================================================================
set -euo pipefail

REPO_EJBCA="devisefutures/ejbca-hsm-ejbca-patches"
REPO_ED25519="devisefutures/ejbca-hsm-ed25519"
ED25519_ASSETS=(
    install-ed25519.sh uninstall-ed25519.sh hsm-installer-lib.sh
    hsm-ed25519-provider.jar hsm-ed25519-listener.jar jna-5.18.1.jar module.xml
    plugin-build.xml ed25519.properties
)
REQUIRED_KEYS=(JAVA_MAJOR WILDFLY_VERSION MARIADB_JDBC_VERSION EJBCA_PATCHES_TAG ED25519_VERSION OS_PACKAGES)

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}$*${NC}"; }
usage()   { sed -n '/^#  USAGE/,/^#  RESULT/p' "$0" | sed 's/^#  \{0,1\}//' | head -n -1; }

CONFIG=""; OUT=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="${2:?--config needs a value}"; shift 2 ;;
        --out)    OUT="${2:?--out needs a value}";       shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) error "Unknown option: $1 (see --help)" ;;
    esac
done
[[ -n "$CONFIG" && -n "$OUT" ]] || error "--config and --out are required (see --help)."
[[ -n "${GITHUB_TOKEN:-}" ]]    || error "GITHUB_TOKEN is not set."
[[ -f "$CONFIG" ]]              || error "Config not found: ${CONFIG}"
# shellcheck disable=SC1090
source "$CONFIG"
for k in "${REQUIRED_KEYS[@]}"; do [[ -n "${!k:-}" ]] || error "Config: ${k} is missing or empty."; done

for t in curl python3 sha256sum apt-get apt-cache dpkg-scanpackages; do
    command -v "$t" >/dev/null || error "Missing tool: ${t} (dpkg-scanpackages: apt install dpkg-dev)"
done
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] \
    || warn "This machine is ${PRETTY_NAME:-unknown}; the .deb files must match the targets (Ubuntu 22.04)."

if [[ -e "$OUT" ]] && [[ -n "$(ls -A "$OUT")" ]]; then error "${OUT} exists and is not empty."; fi
mkdir -p "$OUT"/{os,wildfly,ejbca,addons/ed25519}
OUT="$(readlink -f "$OUT")"

gh_api() { curl -sfL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/vnd.github+json" "https://api.github.com/repos/$1$2"; }

# ---------------------------------------------------------------------------
section "=== 1/6 OS packages (with all dependencies) ==="
# shellcheck disable=SC2086
mapfile -t PKGS < <(apt-cache depends --recurse --no-recommends --no-suggests --no-conflicts \
        --no-breaks --no-replaces --no-enhances ${OS_PACKAGES} | grep '^\w' | sort -u)
info "${#PKGS[@]} packages in the dependency closure."
( cd "$OUT/os"
  for p in "${PKGS[@]}"; do
      apt-get download -qq "$p" 2>/dev/null || warn "  no candidate for ${p} (virtual package, skipped)"
  done
  dpkg-scanpackages --multiversion . /dev/null 2>/dev/null | gzip -9 > Packages.gz )
for p in ${OS_PACKAGES}; do
    ls "$OUT"/os/"${p}"_*.deb >/dev/null 2>&1 || error "Required package ${p} was not downloaded."
done
info "$(ls "$OUT"/os/*.deb | wc -l) .deb files + Packages.gz."

# ---------------------------------------------------------------------------
section "=== 2/6 WildFly ${WILDFLY_VERSION} ==="
curl -fL --progress-bar -o "$OUT/wildfly/wildfly-${WILDFLY_VERSION}.zip" \
    "https://github.com/wildfly/wildfly/releases/download/${WILDFLY_VERSION}/wildfly-${WILDFLY_VERSION}.zip"
unzip -tq "$OUT/wildfly/wildfly-${WILDFLY_VERSION}.zip" >/dev/null || error "WildFly zip is corrupt."

# ---------------------------------------------------------------------------
section "=== 3/6 MariaDB JDBC ${MARIADB_JDBC_VERSION} ==="
JDBC="mariadb-java-client-${MARIADB_JDBC_VERSION}.jar"
MVN="https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/${MARIADB_JDBC_VERSION}/${JDBC}"
curl -fsL -o "$OUT/wildfly/${JDBC}" "$MVN"
expected=$(curl -fsL "${MVN}.sha1" | awk '{print $1}')
actual=$(sha1sum "$OUT/wildfly/${JDBC}" | awk '{print $1}')
[[ "$expected" == "$actual" ]] || error "JDBC driver SHA-1 mismatch (Maven Central)."
info "${JDBC} verified against Maven Central SHA-1."

# ---------------------------------------------------------------------------
section "=== 4/6 EJBCA source ${REPO_EJBCA}@${EJBCA_PATCHES_TAG} ==="
SRC="$OUT/ejbca/ejbca-hsm-ejbca-patches-${EJBCA_PATCHES_TAG}.tar.gz"
curl -fL --progress-bar -H "Authorization: Bearer ${GITHUB_TOKEN}" -o "$SRC" \
    "https://api.github.com/repos/${REPO_EJBCA}/tarball/${EJBCA_PATCHES_TAG}"
tar -tzf "$SRC" >/dev/null || error "EJBCA source archive is corrupt."
tar -xzf "$SRC" -C "$OUT" --wildcards --strip-components=2 \
    '*/installer/install-ejbca.sh' '*/installer/ejbca-install.conf.sample' \
    || error "install-ejbca.sh / ejbca-install.conf.sample not found in ${EJBCA_PATCHES_TAG} (installer/ folder)."
chmod +x "$OUT/install-ejbca.sh"
info "Source archive + installer extracted."

# ---------------------------------------------------------------------------
section "=== 5/6 Ed25519 add-on ${REPO_ED25519}@${ED25519_VERSION} ==="
RELEASE_JSON=$(gh_api "$REPO_ED25519" "/releases/tags/${ED25519_VERSION}") \
    || error "Release ${ED25519_VERSION} not found (check token and tag)."
asset_id() {
    python3 -c 'import json,sys; a=[x["id"] for x in json.loads(sys.argv[1])["assets"] if x["name"]==sys.argv[2]]; print(a[0] if a else "")' \
        "$RELEASE_JSON" "$1"
}
for f in "${ED25519_ASSETS[@]}"; do
    for name in "$f" "$f.sha256"; do
        id=$(asset_id "$name"); [[ -n "$id" ]] || error "Asset ${name} missing from release ${ED25519_VERSION}."
        curl -fsL -H "Authorization: Bearer ${GITHUB_TOKEN}" -H "Accept: application/octet-stream" \
            -o "$OUT/addons/ed25519/${name}" "https://api.github.com/repos/${REPO_ED25519}/releases/assets/${id}"
    done
    expected=$(awk '{print $1}' "$OUT/addons/ed25519/$f.sha256")
    actual=$(sha256sum "$OUT/addons/ed25519/$f" | awk '{print $1}')
    [[ "$expected" == "$actual" ]] || error "Checksum mismatch for ${f}."
    info "  ${f} verified"
done
chmod +x "$OUT"/addons/ed25519/*.sh

# ---------------------------------------------------------------------------
section "=== 6/6 SHA256SUMS ==="
( cd "$OUT" && find . -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs -d '\n' sha256sum > SHA256SUMS )
info "$(wc -l < "$OUT/SHA256SUMS") files listed."

echo ""
echo -e "${BOLD}${GREEN}Bundle ready: ${OUT} ($(du -sh "$OUT" | cut -f1))${NC}"
echo "  Transfer it to the target, e.g.:"
echo "    tar -C $(dirname "$OUT") -czf $(basename "$OUT").tar.gz $(basename "$OUT")"
echo "  On the target extract it so that BUNDLE_DIR in the config points to it."
