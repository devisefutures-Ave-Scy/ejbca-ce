#!/usr/bin/env bash
# =============================================================================
# hsm-installer-lib.sh
# Shared functions for the HSM add-on installers (install-ed25519.sh,
# uninstall-ed25519.sh, and the SM add-on scripts). Sourced, never executed.
#
# Bare-metal only (Ubuntu + WildFly + EJBCA built from source with the add-on plugin hook).
# Offline: nothing here uses the network.
# =============================================================================

# ── Logging ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; BOLD='\033[1m'; RST='\033[0m'

log_info()  { echo -e "${BLU}[INFO]${RST}  $*"; }
log_ok()    { echo -e "${GRN}[OK]${RST}    $*"; }
log_warn()  { echo -e "${YLW}[WARN]${RST}  $*"; }
log_err()   { echo -e "${RED}[ERROR]${RST} $*" >&2; }
log_step()  { echo -e "\n${BOLD}${CYN}── $* ──${RST}"; }
die()       { log_err "$*"; exit 1; }

# ── Confirmation ──────────────────────────────────────────────────────────────
# ask "question" → 0 = yes, 1 = no. ASSUME_YES=true answers yes (--yes).
ask() {
    if [[ "${ASSUME_YES:-false}" == "true" ]]; then
        log_info "--yes given: proceeding ($1)"
        return 0
    fi
    local ans
    read -r -p "$(echo -e "${YLW}?${RST} $1 [y/N] ")" ans || true
    [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]]
}

require_root() { [[ $EUID -eq 0 ]] || die "Run as root (sudo)."; }

# ── Config file ───────────────────────────────────────────────────────────────
# load_config FILE KEY... : file must be root-owned and not group/other
# accessible; every KEY must be set and non-empty. No defaults.
load_config() {
    local file="$1"; shift
    [[ -f "$file" ]] || die "Config file not found: ${file}"
    local owner perms
    owner=$(stat -c '%U' "$file"); perms=$(stat -c '%a' "$file")
    [[ "$owner" == "root" ]]     || die "Config ${file} must be owned by root (is: ${owner})."
    [[ "${perms: -2}" == "00" ]] || die "Config ${file} must not be accessible by group/others (chmod 600; is: ${perms})."
    # shellcheck disable=SC1090
    source "$file"
    local k missing=()
    for k in "$@"; do
        [[ -n "${!k:-}" ]] || missing+=("$k")
    done
    [[ ${#missing[@]} -eq 0 ]] || die "Config ${file}: missing or empty values: ${missing[*]}"
}

# ── Integrity ─────────────────────────────────────────────────────────────────
# verify_sidecars DIR FILE... : each FILE must have FILE.sha256 next to it
# (first field = hex digest) and match it.
verify_sidecars() {
    local dir="$1"; shift
    local f expected actual
    for f in "$@"; do
        [[ -f "${dir}/${f}" ]]        || die "Missing file: ${dir}/${f}"
        [[ -f "${dir}/${f}.sha256" ]] || die "Missing checksum file: ${dir}/${f}.sha256"
        expected=$(awk '{print $1}' "${dir}/${f}.sha256")
        actual=$(sha256sum "${dir}/${f}" | awk '{print $1}')
        [[ "$expected" == "$actual" ]] || die "Checksum mismatch for ${f}\n  expected: ${expected}\n  actual:   ${actual}"
    done
    log_ok "Checksums verified: $*"
}

# ── EJBCA source ──────────────────────────────────────────────────────────────
ejbca_source_version() {
    grep '^app.version.number=' "${1}/src/internal.properties" 2>/dev/null \
        | cut -d= -f2 | tr -d ' \r'
}

# Release versions are <generation>.<ejbca-code>.<patch>, e.g. 2.963.0, where
# <ejbca-code> is the EJBCA version without dots (9.6.3 → 963).
ejbca_version_code() { echo "${1//./}"; }                  # 9.6.3 → 963
release_ejbca_code() { local v="${1#v}"; v="${v#*.}"; echo "${v%%.*}"; }  # 2.963.0 → 963

# The fork's plugin hook: build.xml passes ejbca.jboss-ds.xml to plugins and the
# jboss-deployment-structure.xml template carries the insertion markers.
ejbca_has_plugin_hook() {
    local home="$1"
    grep -q 'ejbca.jboss-ds.xml' "${home}/build.xml" 2>/dev/null \
      && grep -q '@plugin-dependencies@' "${home}/src/deploy/ear/META-INF/jboss-deployment-structure.xml" 2>/dev/null
}

# ── WildFly management CLI ────────────────────────────────────────────────────
# wf_cli "<command>" : prints output; returns jboss-cli's exit code
# (non-zero when the operation fails or the resource does not exist).
wf_cli() { "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect --command="$1"; }

wf_running() {
    "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect \
        --command=':read-attribute(name=server-state)' 2>/dev/null | grep -q '"running"'
}

wf_wait_running() {
    local max=120 i=0
    until wf_running; do
        sleep 3; i=$((i+3))
        [[ $i -ge $max ]] && die "WildFly not running after ${max}s. Check ${WILDFLY_HOME}/standalone/log/server.log"
    done
}

wf_reload() {
    log_info "Reloading WildFly..."
    "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect --command=':reload' >/dev/null 2>&1 || true
    sleep 6
    wf_wait_running
    log_ok "WildFly reloaded."
}

# Names of the entries in /subsystem=ee global-modules, one per line, in order.
wf_global_module_names() {
    wf_cli '/subsystem=ee:read-attribute(name=global-modules)' \
        | grep -o '"name" => "[^"]*"' | sed 's/.*=> "//; s/"$//'
}

# ── EJBCA health ──────────────────────────────────────────────────────────────
ejbca_health_ok() {
    curl -s --max-time 5 "http://localhost:${HTTP_PORT}/ejbca/publicweb/healthcheck/ejbcahealth" 2>/dev/null \
        | grep -q '^ALLOK'
}
