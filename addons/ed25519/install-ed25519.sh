#!/usr/bin/env bash
# shellcheck disable=SC2034  # ASSUME_YES is used by ask() in hsm-installer-lib.sh
# =============================================================================
# install-ed25519.sh  —  HSM Ed25519 add-on for EJBCA v2 (bare-metal, offline)
# =============================================================================
# Usage:
#   sudo ./install-ed25519.sh --config FILE --mode MODE [--yes]
#
#   --config FILE   ejbca-install.conf (same file as install-ejbca.sh)  [required]
#   --mode MODE     pre-deploy       before "ant deployear": WildFly module,
#                                    standalone.xml (via jboss-cli), EJBCA
#                                    build plugin. WildFly must be running.
#                   verify           after deploy: checks EAR, WildFly config,
#                                    StartupBean registration, healthcheck
#                   migrate-from-7x  (not available in this release)   [required]
#   --yes           do not ask for confirmation after the plan
#
# Shipped inside the EJBCA source at
# $EJBCA_HOME/addons/ed25519/, next to the add-on files it installs.
# It can also run from any other folder holding the release files; they are
# then copied to $EJBCA_HOME/addons/ed25519/. Nothing is downloaded; every
# file is checked against its .sha256 before use.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hsm-installer-lib.sh
source "${SCRIPT_DIR}/hsm-installer-lib.sh"

# ── Add-on constants ──────────────────────────────────────────────────────────
ADDON_NAME="Ed25519"
ADDON_ID="ed25519"
MODULE_NAME="com.devisefutures.ed25519"
PROVIDER_NAME="hsm-ed25519"
STARTUP_BEAN="HsmEd25519StartupBean"
LISTENER_JAR="hsm-ed25519-listener.jar"

MODULE_FILES=("hsm-ed25519-provider.jar" "jna-5.18.1.jar" "module.xml")
PLUGIN_FILES=("${LISTENER_JAR}" "plugin-build.xml")
PLUGIN_PROPS="${ADDON_ID}.properties"

REQUIRED_KEYS=(EJBCA_HOME WILDFLY_HOME WILDFLY_USER HTTP_PORT EJBCA_VERSION ED25519_VERSION)

show_usage() { sed -n '/^# Usage:/,/^# ===/p' "$0" | grep -v '^# ===' | sed 's/^# \{0,1\}//'; }

# ── Arguments ─────────────────────────────────────────────────────────────────
CONFIG=""; MODE=""; ASSUME_YES=false   # ASSUME_YES is read by ask() in hsm-installer-lib.sh
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="${2:?--config needs a value}"; shift 2 ;;
        --mode)   MODE="${2:?--mode needs a value}";     shift 2 ;;
        --yes)    ASSUME_YES=true; shift ;;
        --help|-h) show_usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done
[[ -n "$CONFIG" ]] || die "--config is required (see --help)."
[[ -n "$MODE"   ]] || die "--mode is required (see --help)."

# ── Derived paths (after config) ──────────────────────────────────────────────
set_paths() {
    MODULE_DIR="${WILDFLY_HOME}/modules/$(echo "$MODULE_NAME" | tr '.' '/')/main"
    PLUGIN_DIR="${EJBCA_HOME}/addons/${ADDON_ID}"
    PLUGIN_PROPS_DEST="${EJBCA_HOME}/conf/plugins/${PLUGIN_PROPS}"
}

# =============================================================================
# MODE pre-deploy
# =============================================================================
pre_deploy() {
    log_step "Checks"
    verify_sidecars "$SCRIPT_DIR" "${MODULE_FILES[@]}" "${PLUGIN_FILES[@]}" "$PLUGIN_PROPS"
    if [[ -f "${SCRIPT_DIR}/VERSION" ]]; then
        local shipped; shipped="$(tr -d ' \r\n' < "${SCRIPT_DIR}/VERSION")"
        [[ "$shipped" == "$ED25519_VERSION" ]] \
            || die "Add-on files in ${SCRIPT_DIR} are release ${shipped}; config ED25519_VERSION is ${ED25519_VERSION}."
        log_ok "Add-on release ${shipped}."
    fi

    [[ -f "${EJBCA_HOME}/build.xml" ]] || die "No EJBCA source at ${EJBCA_HOME}."
    local found; found="$(ejbca_source_version "$EJBCA_HOME")"
    [[ "$found" == "$EJBCA_VERSION" ]] \
        || die "EJBCA source is ${found:-unknown}; config EJBCA_VERSION is ${EJBCA_VERSION}."
    [[ "$(release_ejbca_code "$ED25519_VERSION")" == "$(ejbca_version_code "$EJBCA_VERSION")" ]] \
        || die "Add-on ${ED25519_VERSION} is not built for EJBCA ${EJBCA_VERSION} (expected ?.$(ejbca_version_code "$EJBCA_VERSION").x)."
    log_ok "EJBCA source version ${found}."
    ejbca_has_plugin_hook "$EJBCA_HOME" \
        || die "EJBCA source at ${EJBCA_HOME} has no add-on plugin hook."
    log_ok "EJBCA plugin hook present."

    [[ -x "${WILDFLY_HOME}/bin/jboss-cli.sh" ]] || die "No WildFly at ${WILDFLY_HOME}."
    wf_running || die "WildFly is not running. Start it first (systemctl start wildfly-standalone)."
    log_ok "WildFly running."
    wf_cli '/subsystem=elytron/aggregate-providers=combined-providers:read-resource' >/dev/null 2>&1 \
        || die "Elytron aggregate-providers 'combined-providers' not found in standalone.xml - unexpected WildFly configuration."

    log_step "Plan"
    cat <<EOF
  Add-on            ${ADDON_NAME} ${ED25519_VERSION} (for EJBCA ${EJBCA_VERSION})
  WildFly module    ${MODULE_DIR}/  <- ${MODULE_FILES[*]}
  standalone.xml    (jboss-cli, then reload)
                      ee global-modules            += ${MODULE_NAME}
                      elytron provider-loader      ${PROVIDER_NAME} (module ${MODULE_NAME})
                      elytron combined-providers   += ${PROVIDER_NAME}
  EJBCA plugin      ${PLUGIN_DIR}/  <- ${PLUGIN_FILES[*]}
                    ${PLUGIN_PROPS_DEST}
  Next step         ant deployear (the build includes the add-on from now on)
EOF
    ask "Proceed?" || { log_info "Aborted."; exit 0; }

    log_step "WildFly module"
    mkdir -p "$MODULE_DIR"
    local f
    for f in "${MODULE_FILES[@]}"; do
        cp "${SCRIPT_DIR}/${f}" "${MODULE_DIR}/${f}"
    done
    chown -R "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/modules/com/devisefutures"
    log_ok "Module installed: ${MODULE_DIR}"

    log_step "standalone.xml"
    local changed=false
    if wf_global_module_names | grep -qx "$MODULE_NAME"; then
        log_info "Global module ${MODULE_NAME} already present."
    else
        wf_cli "/subsystem=ee:list-add(name=global-modules,value={name=${MODULE_NAME},slot=main})" >/dev/null \
            || die "Failed to add global module ${MODULE_NAME}."
        log_ok "Global module added."; changed=true
    fi
    if wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:read-resource" >/dev/null 2>&1; then
        log_info "Provider-loader ${PROVIDER_NAME} already present."
    else
        wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:add(module=${MODULE_NAME})" >/dev/null \
            || die "Failed to add provider-loader ${PROVIDER_NAME}."
        log_ok "Provider-loader added."; changed=true
    fi
    if wf_cli '/subsystem=elytron/aggregate-providers=combined-providers:read-attribute(name=providers)' \
            | grep -q "\"${PROVIDER_NAME}\""; then
        log_info "${PROVIDER_NAME} already in combined-providers."
    else
        wf_cli "/subsystem=elytron/aggregate-providers=combined-providers:list-add(name=providers,value=${PROVIDER_NAME})" >/dev/null \
            || die "Failed to add ${PROVIDER_NAME} to combined-providers."
        log_ok "Added to combined-providers."; changed=true
    fi
    if $changed; then wf_reload; fi

    log_step "EJBCA build plugin"
    mkdir -p "$PLUGIN_DIR" "$(dirname "$PLUGIN_PROPS_DEST")"
    if [[ "$(readlink -f "$SCRIPT_DIR")" == "$(readlink -f "$PLUGIN_DIR")" ]]; then
        log_info "Plugin files already in place (shipped with the EJBCA source)."
    else
        for f in "${PLUGIN_FILES[@]}"; do
            cp "${SCRIPT_DIR}/${f}" "${PLUGIN_DIR}/${f}"
        done
    fi
    sed "s#@EJBCA_HOME@#${EJBCA_HOME}#g" "${SCRIPT_DIR}/${PLUGIN_PROPS}" > "$PLUGIN_PROPS_DEST"
    grep -q "^plugin.ejbca.ant.file=${PLUGIN_DIR}/plugin-build.xml$" "$PLUGIN_PROPS_DEST" \
        || die "Unexpected content in ${PLUGIN_PROPS_DEST}."
    log_ok "Plugin installed: ${PLUGIN_DIR}, ${PLUGIN_PROPS_DEST}"

    echo ""
    log_ok "${ADDON_NAME} pre-deploy complete."
    log_info "Next: build and deploy EJBCA (cd ${EJBCA_HOME} && ant clean deployear),"
    log_info "      then: $0 --config ${CONFIG} --mode verify"
}

# =============================================================================
# MODE verify
# =============================================================================
FAILS=0
check() {   # check "description" command [args...]  (command may be a function)
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then log_ok "$desc"; else log_err "$desc"; FAILS=$((FAILS+1)); fi
}

has_global_module()   { wf_global_module_names | grep -qx "$MODULE_NAME"; }
has_provider_loader() { wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:read-resource"; }
ear_has_entry()       { unzip -l "$EAR" | awk '{print $4}' | grep -qx "$1"; }
ear_file_contains()   { unzip -p "$EAR" "$1" | grep -qF "$2"; }
bean_registered()     { grep "$STARTUP_BEAN" "$SERVER_LOG" | grep -q 'registration: true'; }

verify() {
    EAR="${EJBCA_HOME}/dist/ejbca.ear"
    SERVER_LOG="${WILDFLY_HOME}/standalone/log/server.log"
    local dep="${WILDFLY_HOME}/standalone/deployments"

    log_step "WildFly"
    local f
    for f in "${MODULE_FILES[@]}"; do
        check "Module file ${f}" test -f "${MODULE_DIR}/${f}"
    done
    check "WildFly running"                        wf_running
    check "Global module ${MODULE_NAME}"           has_global_module
    check "Provider-loader ${PROVIDER_NAME}"       has_provider_loader

    log_step "EAR"
    check "Plugin declared (${PLUGIN_PROPS_DEST})" test -f "$PLUGIN_PROPS_DEST"
    check "EAR built (${EAR})"                     test -f "$EAR"
    check "Listener at EAR root"                   ear_has_entry "$LISTENER_JAR"
    check "Listener in EAR lib/"                   ear_has_entry "lib/${LISTENER_JAR}"
    check "application.xml declares the listener"  ear_file_contains META-INF/application.xml "<ejb>${LISTENER_JAR}</ejb>"
    check "jboss-deployment-structure.xml module"  ear_file_contains META-INF/jboss-deployment-structure.xml "module name=\"${MODULE_NAME}\""
    check "EAR deployed (ejbca.ear.deployed)"      test -f "${dep}/ejbca.ear.deployed"
    check "No failed deployment marker"            test ! -f "${dep}/ejbca.ear.failed"

    log_step "Runtime"
    check "${STARTUP_BEAN} registration: true (server.log)" bean_registered
    check "EJBCA healthcheck ALLOK"                ejbca_health_ok

    echo ""
    if [[ $FAILS -eq 0 ]]; then
        log_ok "${ADDON_NAME} add-on verified."
    else
        die "${FAILS} check(s) failed. See ${SERVER_LOG}"
    fi
}

# =============================================================================
main() {
    echo -e "\n${BOLD}HSM ${ADDON_NAME} add-on — mode ${MODE}${RST}"
    echo -e "────────────────────────────────────────────"
    require_root
    load_config "$CONFIG" "${REQUIRED_KEYS[@]}"
    set_paths
    case "$MODE" in
        pre-deploy)      pre_deploy ;;
        verify)          verify ;;
        migrate-from-7x) die "Mode migrate-from-7x is not available in this release." ;;
        *)               die "Unknown mode: ${MODE} (pre-deploy | verify | migrate-from-7x)" ;;
    esac
}

main
