#!/usr/bin/env bash
# shellcheck disable=SC2034  # ASSUME_YES is used by ask() in hsm-installer-lib.sh
# =============================================================================
# uninstall-ed25519.sh  —  remove the HSM Ed25519 add-on (bare-metal)
# =============================================================================
# Usage:
#   sudo ./uninstall-ed25519.sh --config FILE [--yes]
#
#   --config FILE   ejbca-install.conf (same file as install-ejbca.sh)  [required]
#   --yes           do not ask for confirmation after the plan
#
# Refuses to run while any crypto token in the database uses the Ed25519
# token type: EJBCA could not load those tokens (and their CAs) without it.
#
# The add-on files in $EJBCA_HOME/addons/ed25519/ are part of the EJBCA source
# and are kept; removing conf/plugins/ed25519.properties deactivates them.
#
# Order matters: the EAR is rebuilt and redeployed WITHOUT the add-on first,
# and only then is the WildFly module removed, so the running EAR never
# depends on a module that is gone.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=hsm-installer-lib.sh
source "${SCRIPT_DIR}/hsm-installer-lib.sh"

ADDON_NAME="Ed25519"
ADDON_ID="ed25519"
MODULE_NAME="com.devisefutures.ed25519"
PROVIDER_NAME="hsm-ed25519"
TOKEN_CLASS="HsmEd25519CryptoToken"

REQUIRED_KEYS=(EJBCA_HOME WILDFLY_HOME HTTP_PORT DB_NAME DB_USER DB_PASS)

show_usage() { sed -n '/^# Usage:/,/^# ===/p' "$0" | grep -v '^# ===' | sed 's/^# \{0,1\}//'; }

CONFIG=""; ASSUME_YES=false   # ASSUME_YES is read by ask() in hsm-installer-lib.sh
while [[ $# -gt 0 ]]; do
    case "$1" in
        --config) CONFIG="${2:?--config needs a value}"; shift 2 ;;
        --yes)    ASSUME_YES=true; shift ;;
        --help|-h) show_usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
done
[[ -n "$CONFIG" ]] || die "--config is required (see --help)."

main() {
    echo -e "\n${BOLD}HSM ${ADDON_NAME} add-on — uninstall${RST}"
    echo -e "────────────────────────────────────────────"
    require_root
    load_config "$CONFIG" "${REQUIRED_KEYS[@]}"

    local module_dir
    module_dir="${WILDFLY_HOME}/modules/$(echo "$MODULE_NAME" | tr '.' '/')/main"
    local plugin_dir="${EJBCA_HOME}/addons/${ADDON_ID}"
    local plugin_props="${EJBCA_HOME}/conf/plugins/${ADDON_ID}.properties"

    log_step "Checks"
    wf_running || die "WildFly is not running. Start it first (systemctl start wildfly-standalone)."
    local in_use
    in_use=$(mysql -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -sN \
        -e "SELECT COUNT(*) FROM CryptoTokenData WHERE tokenType LIKE '%${TOKEN_CLASS}%';" 2>/dev/null) \
        || die "Could not query CryptoTokenData - cannot confirm the add-on is unused."
    [[ "$in_use" -eq 0 ]] || die "${in_use} crypto token(s) use ${TOKEN_CLASS}. Delete them (and their CAs) in EJBCA before uninstalling."
    log_ok "No crypto token uses ${TOKEN_CLASS}."

    log_step "Plan"
    cat <<EOF
  1. Deactivate the build plugin remove ${plugin_props}
                                 (the add-on files in ${plugin_dir}/ stay: they are
                                 part of the EJBCA source and unused without it)
  2. Rebuild and redeploy EJBCA  cd ${EJBCA_HOME} && ant clean deployear  (wait for ALLOK)
  3. standalone.xml (jboss-cli)  remove ${PROVIDER_NAME} from combined-providers,
                                 remove provider-loader ${PROVIDER_NAME},
                                 remove global module ${MODULE_NAME}, reload
  4. Remove WildFly module       ${module_dir}/
EOF
    ask "Proceed?" || { log_info "Aborted."; exit 0; }

    log_step "1. EJBCA build plugin"
    rm -f "$plugin_props"
    log_ok "Plugin deactivated."

    log_step "2. Rebuild and redeploy"
    export APPSRV_HOME="${WILDFLY_HOME}"
    ( cd "${EJBCA_HOME}" && ant -q clean deployear ) || die "ant clean deployear failed."
    local i=0
    sleep 10
    until ejbca_health_ok; do
        sleep 5; i=$((i+5))
        [[ $i -ge 300 ]] && die "EJBCA not ALLOK after 300s. Check ${WILDFLY_HOME}/standalone/log/server.log"
    done
    log_ok "EJBCA redeployed without the add-on."

    log_step "3. standalone.xml"
    if wf_cli '/subsystem=elytron/aggregate-providers=combined-providers:read-attribute(name=providers)' \
            | grep -q "\"${PROVIDER_NAME}\""; then
        wf_cli "/subsystem=elytron/aggregate-providers=combined-providers:list-remove(name=providers,value=${PROVIDER_NAME})" >/dev/null
        log_ok "Removed from combined-providers."
    fi
    if wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:read-resource" >/dev/null 2>&1; then
        wf_cli "/subsystem=elytron/provider-loader=${PROVIDER_NAME}:remove" >/dev/null
        log_ok "Provider-loader removed."
    fi
    local idx
    idx=$(wf_global_module_names | grep -nx "$MODULE_NAME" | cut -d: -f1 || true)
    if [[ -n "$idx" ]]; then
        wf_cli "/subsystem=ee:list-remove(name=global-modules,index=$((idx-1)))" >/dev/null
        log_ok "Global module removed."
    fi
    wf_reload

    log_step "4. WildFly module"
    rm -rf "$module_dir"
    rmdir --ignore-fail-on-non-empty "$(dirname "$module_dir")" "${WILDFLY_HOME}/modules/com/devisefutures" 2>/dev/null || true
    log_ok "Module removed."

    echo ""
    log_ok "${ADDON_NAME} add-on uninstalled."
}

main
