#!/usr/bin/env bash
# =============================================================================
#  fetch-bundle.sh  -  build the offline bundle for install-ejbca.sh
# =============================================================================
#  Run on an ONLINE Ubuntu 22.04 machine (same release as the targets), then
#  copy the resulting folder to the offline target.
#
#  USAGE
#    export GITHUB_TOKEN=<token>   # ONLY if EJBCA_REPO is private: fine-grained,
#                                  # Contents: Read-only on that repository only
#    ./fetch-bundle.sh --config FILE --out DIR
#
#    --config FILE   ejbca-install.conf - only the version keys are used here
#                    (JAVA_MAJOR, WILDFLY_VERSION, MARIADB_JDBC_VERSION,
#                     EJBCA_REPO, EJBCA_PATCHES_TAG, ED25519_VERSION, OS_PACKAGES)
#    --out DIR       bundle folder to create (must not exist or be empty)
#
#  Needs on this machine (install first):
#    sudo apt-get update && sudo apt-get install -y curl dpkg-dev unzip
#
#  RESULT
#    DIR/install-ejbca.sh, DIR/ejbca-install.conf.sample   (from the EJBCA tag)
#    DIR/os/*.deb + Packages.gz                             (local apt repository)
#    DIR/wildfly/wildfly-<ver>.zip, mariadb-java-client-<ver>.jar
#    DIR/ejbca/ejbca-<tag>.tar.gz
#    DIR/SHA256SUMS                                         (every file above)
#  The Utimaco PKCS#11 library is NOT part of the bundle (client-provided).
# =============================================================================
set -euo pipefail

REQUIRED_KEYS=(JAVA_MAJOR WILDFLY_VERSION MARIADB_JDBC_VERSION EJBCA_REPO EJBCA_PATCHES_TAG ED25519_VERSION OS_PACKAGES)

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
# Public repository: anonymous download. Private repository: GITHUB_TOKEN.
AUTH=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then AUTH=(-H "Authorization: Bearer ${GITHUB_TOKEN}"); fi
[[ -f "$CONFIG" ]]              || error "Config not found: ${CONFIG}"
# shellcheck disable=SC1090
source "$CONFIG"
for k in "${REQUIRED_KEYS[@]}"; do [[ -n "${!k:-}" ]] || error "Config: ${k} is missing or empty."; done

for t in curl sha256sum unzip apt-get apt-cache dpkg-scanpackages; do
    command -v "$t" >/dev/null \
        || error "Missing tool: ${t}. Install: sudo apt-get install -y curl dpkg-dev unzip"
done
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "22.04" ]] \
    || warn "This machine is ${PRETTY_NAME:-unknown}; the .deb files must match the targets (Ubuntu 22.04)."

if [[ -e "$OUT" ]] && [[ -n "$(ls -A "$OUT")" ]]; then error "${OUT} exists and is not empty."; fi
mkdir -p "$OUT"/{os,wildfly,ejbca}
OUT="$(readlink -f "$OUT")"


# ---------------------------------------------------------------------------
section "=== 1/5 OS packages (with all dependencies) ==="
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
section "=== 2/5 WildFly ${WILDFLY_VERSION} ==="
curl -fL --progress-bar -o "$OUT/wildfly/wildfly-${WILDFLY_VERSION}.zip" \
    "https://github.com/wildfly/wildfly/releases/download/${WILDFLY_VERSION}/wildfly-${WILDFLY_VERSION}.zip"
unzip -tq "$OUT/wildfly/wildfly-${WILDFLY_VERSION}.zip" >/dev/null || error "WildFly zip is corrupt."

# ---------------------------------------------------------------------------
section "=== 3/5 MariaDB JDBC ${MARIADB_JDBC_VERSION} ==="
JDBC="mariadb-java-client-${MARIADB_JDBC_VERSION}.jar"
MVN="https://repo1.maven.org/maven2/org/mariadb/jdbc/mariadb-java-client/${MARIADB_JDBC_VERSION}/${JDBC}"
curl -fsL -o "$OUT/wildfly/${JDBC}" "$MVN"
expected=$(curl -fsL "${MVN}.sha1" | awk '{print $1}')
actual=$(sha1sum "$OUT/wildfly/${JDBC}" | awk '{print $1}')
[[ "$expected" == "$actual" ]] || error "JDBC driver SHA-1 mismatch (Maven Central)."
info "${JDBC} verified against Maven Central SHA-1."

# ---------------------------------------------------------------------------
section "=== 4/5 EJBCA source + add-ons ${EJBCA_REPO}@${EJBCA_PATCHES_TAG} ==="
SRC="$OUT/ejbca/ejbca-${EJBCA_PATCHES_TAG}.tar.gz"
curl -fL --progress-bar "${AUTH[@]}" -o "$SRC" \
    "https://api.github.com/repos/${EJBCA_REPO}/tarball/${EJBCA_PATCHES_TAG}" \
    || error "Could not download ${EJBCA_REPO}@${EJBCA_PATCHES_TAG}. Check the repository and tag; for a private repository set GITHUB_TOKEN."
tar -tzf "$SRC" >/dev/null || error "EJBCA source archive is corrupt."
tar -xzf "$SRC" -C "$OUT" --wildcards --strip-components=2 \
    '*/installer/install-ejbca.sh' '*/installer/ejbca-install.conf.sample' \
    || error "install-ejbca.sh / ejbca-install.conf.sample not found in ${EJBCA_PATCHES_TAG} (installer/ folder)."
chmod +x "$OUT/install-ejbca.sh"
info "Source archive + installer extracted."

# The add-on is shipped inside the source: check its release matches the config.
SHIPPED=$(tar -xzOf "$SRC" --wildcards '*/addons/ed25519/VERSION' 2>/dev/null | tr -d ' \r\n') \
    || error "No addons/ed25519/VERSION in ${EJBCA_PATCHES_TAG} (run the 'Update add-on' workflow before tagging)."
[[ "$SHIPPED" == "$ED25519_VERSION" ]] \
    || error "${EJBCA_PATCHES_TAG} ships Ed25519 ${SHIPPED}; config ED25519_VERSION is ${ED25519_VERSION}."
info "Ed25519 add-on ${SHIPPED} is part of the source."

# ---------------------------------------------------------------------------
section "=== 5/5 SHA256SUMS ==="
( cd "$OUT" && find . -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs -d '\n' sha256sum > SHA256SUMS )
info "$(wc -l < "$OUT/SHA256SUMS") files listed."

echo ""
echo -e "${BOLD}${GREEN}Bundle ready: ${OUT} ($(du -sh "$OUT" | cut -f1))${NC}"
echo "  Transfer it to the target, e.g.:"
echo "    tar -C $(dirname "$OUT") -czf $(basename "$OUT").tar.gz $(basename "$OUT")"
echo "  On the target extract it so that BUNDLE_DIR in the config points to it."
