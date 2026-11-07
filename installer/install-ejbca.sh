#!/usr/bin/env bash
# =============================================================================
#  install-ejbca.sh  -  EJBCA v2 (DeviseFutures EJBCA-CE fork) installer
# =============================================================================
#  Target : Ubuntu 22.04 LTS (x86_64), offline
#  DB     : local MariaDB
#  AppSrv : WildFly (HTTP / HTTPS on separate ports)
#  Ref    : https://docs.keyfactor.com/ejbca-software/latest/installation
#
#  USAGE
#    sudo ./install-ejbca.sh --config FILE --mode MODE [--addon INSTALLER]... [--yes]
#
#    --config FILE      ejbca-install.conf (see ejbca-install.conf.sample)   [required]
#    --mode MODE        fresh            new host, new database, new ManagementCA
#                       upgrade-from-7x  (not available in this release)     [required]
#    --addon INSTALLER  add-on installer to run at its hook points, e.g.
#                       /opt/ejbca-bundle/addons/ed25519/install-ed25519.sh
#                       (repeat for several add-ons)                         [optional]
#    --yes              do not ask for confirmation after the plan
#
#  The script never uses the network. Everything comes from BUNDLE_DIR
#  (see fetch-bundle.sh). It never guesses: missing config values, a non-empty
#  target (existing WildFly, EJBCA home or database) or a failed check stop it
#  before anything is changed.
#
#  PHASES (mode fresh)
#     1  Plan            validate config, print the plan, confirm
#     2  Bundle          verify SHA256SUMS of the offline bundle
#     3  Pre-flight      OS, empty target, HSM library present
#     4  Packages        local apt repository + OS_PACKAGES
#     5  Database        MariaDB: secure, create database and user
#     6  WildFly         unpack + configure (service, datasource, TLS listeners...)
#     7  EJBCA source    unpack the ejbca-patches tag, check version
#     8  EJBCA conf      write conf/*.properties
#     9  Add-ons         <addon> --mode pre-deploy           (only with --addon)
#    10  Build + deploy  ant clean deployear, wait until EJBCA is up
#    11  Install         ant runinstall, ant deploy-keystore, reload
#    12  Add-ons         <addon> --mode verify               (only with --addon)
#    13  Finalise        ownership, service enabled, firewall, summary
# =============================================================================
set -euo pipefail

# ---------------------------------------------------------------------------
# Fixed values (WildFly's systemd unit hard-codes /opt/wildfly and user wildfly)
# ---------------------------------------------------------------------------
readonly FIXED_WILDFLY_HOME="/opt/wildfly"
readonly FIXED_WILDFLY_USER="wildfly"
readonly FIXED_WILDFLY_SERVICE="wildfly-standalone"

REQUIRED_KEYS=(
    JAVA_MAJOR WILDFLY_VERSION MARIADB_JDBC_VERSION EJBCA_PATCHES_TAG EJBCA_VERSION OS_PACKAGES
    BUNDLE_DIR EJBCA_HOME WILDFLY_HOME WILDFLY_USER WILDFLY_SERVICE
    EJBCA_HOSTNAME DN_SUFFIX HTTP_PORT HTTPS_PORT HEAP_SIZE_MB
    DB_ROOT_PASS DB_NAME DB_USER DB_PASS
    PBE_ENCRYPTION_KEY KS_PASS TS_PASS SUPERADMIN_PASS
    P11_LIB_NAME P11_LIB_FILE
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }
section() { echo -e "\n${BOLD}${CYAN}$*${NC}"; }

usage() { sed -n '/^#  USAGE/,/^#  The script/p' "$0" | sed 's/^#  \{0,1\}//' | head -n -1; }

load_config() {
    local file="$1"
    [[ -f "$file" ]] || error "Config file not found: ${file}"
    local owner perms
    owner=$(stat -c '%U' "$file"); perms=$(stat -c '%a' "$file")
    [[ "$owner" == "root" ]] || error "Config ${file} must be owned by root (is: ${owner})."
    [[ "${perms: -2}" == "00" ]] || error "Config ${file} must not be accessible by group/others (chmod 600; is: ${perms})."
    # shellcheck disable=SC1090
    source "$file"
    local missing=()
    for k in "${REQUIRED_KEYS[@]}"; do
        [[ -n "${!k:-}" ]] || missing+=("$k")
    done
    [[ ${#missing[@]} -eq 0 ]] || error "Config ${file}: missing or empty values: ${missing[*]}"
    [[ "$WILDFLY_HOME"    == "$FIXED_WILDFLY_HOME"    ]] || error "WILDFLY_HOME must be ${FIXED_WILDFLY_HOME} (fixed by WildFly's systemd unit)."
    [[ "$WILDFLY_USER"    == "$FIXED_WILDFLY_USER"    ]] || error "WILDFLY_USER must be ${FIXED_WILDFLY_USER} (fixed by WildFly's systemd unit)."
    [[ "$WILDFLY_SERVICE" == "$FIXED_WILDFLY_SERVICE" ]] || error "WILDFLY_SERVICE must be ${FIXED_WILDFLY_SERVICE}."
}

wait_for_wildfly() {
    local max=120 i=0
    info "Waiting for WildFly to reach running state (up to ${max}s)..."
    until "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect \
            --command=':read-attribute(name=server-state)' 2>/dev/null \
            | grep -q '"running"'; do
        sleep 3; i=$((i+3))
        [[ $i -ge $max ]] && \
            error "WildFly did not start within ${max}s. Check: ${WILDFLY_HOME}/standalone/log/server.log"
    done
    info "WildFly is running."
}

# jboss-cli with one retry when a command lands in a reload window.
cli() {
    local output exit_code=0
    output=$("${WILDFLY_HOME}/bin/jboss-cli.sh" --connect "$@" 2>&1) || exit_code=$?
    if [[ $exit_code -ne 0 ]] && echo "${output}" | grep -q "CancellationException"; then
        warn "CLI command cancelled (WildFly mid-reload) - retrying in 8s..."
        sleep 8
        "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect "$@"
    else
        echo "${output}"
        return $exit_code
    fi
}

cli_reload() {
    sleep 3
    "${WILDFLY_HOME}/bin/jboss-cli.sh" --connect ':reload' 2>/dev/null || true
    sleep 6
    wait_for_wildfly
}

mysql_root() { mysql -u root -p"${DB_ROOT_PASS}" "$@"; }

# ---------------------------------------------------------------------------
# Arguments
# ---------------------------------------------------------------------------
CONFIG=""; MODE=""; ASSUME_YES=false; ADDONS=()

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --config) CONFIG="${2:?--config needs a value}"; shift 2 ;;
            --mode)   MODE="${2:?--mode needs a value}";     shift 2 ;;
            --addon)  ADDONS+=("${2:?--addon needs a value}"); shift 2 ;;
            --yes)    ASSUME_YES=true; shift ;;
            --help|-h) usage; exit 0 ;;
            *) error "Unknown option: $1 (see --help)" ;;
        esac
    done
    [[ -n "$CONFIG" ]] || error "--config is required (see --help)."
    [[ -n "$MODE"   ]] || error "--mode is required (see --help)."
    case "$MODE" in
        fresh) ;;
        upgrade-from-7x) error "Mode upgrade-from-7x is not available in this release." ;;
        *) error "Unknown mode: ${MODE} (fresh | upgrade-from-7x)" ;;
    esac
    CONFIG="$(readlink -f "$CONFIG")"
    local a
    for a in "${ADDONS[@]}"; do
        [[ -x "$a" ]] || error "Add-on installer not found or not executable: ${a}"
    done
}

# ---------------------------------------------------------------------------
# PHASE 1 - PLAN
# ---------------------------------------------------------------------------
phase1_plan() {
    section "=== Phase 1: Plan ==="
    load_config "$CONFIG"

    WILDFLY_INSTALL_DIR="/opt/wildfly-${WILDFLY_VERSION}"
    WILDFLY_ZIP="${BUNDLE_DIR}/wildfly/wildfly-${WILDFLY_VERSION}.zip"
    MARIADB_JDBC_JAR="mariadb-java-client-${MARIADB_JDBC_VERSION}.jar"
    MARIADB_JDBC_FILE="${BUNDLE_DIR}/wildfly/${MARIADB_JDBC_JAR}"
    EJBCA_ARCHIVE="${BUNDLE_DIR}/ejbca/ejbca-hsm-ejbca-patches-${EJBCA_PATCHES_TAG}.tar.gz"
    WILDFLY_MAJOR="${WILDFLY_VERSION%%.*}"

    echo ""
    echo -e "${BOLD}======================================================${NC}"
    echo -e "${BOLD}  Installation plan  (mode: ${MODE})${NC}"
    echo -e "${BOLD}======================================================${NC}"
    printf "  %-22s %s\n" "Config:"        "${CONFIG}"
    printf "  %-22s %s\n" "Bundle:"        "${BUNDLE_DIR}"
    printf "  %-22s %s\n" "OS packages:"   "${OS_PACKAGES}"
    printf "  %-22s %s\n" "WildFly:"       "${WILDFLY_VERSION} -> ${WILDFLY_INSTALL_DIR} (link ${WILDFLY_HOME})"
    printf "  %-22s %s\n" "MariaDB JDBC:"  "${MARIADB_JDBC_VERSION}"
    printf "  %-22s %s\n" "EJBCA source:"  "ejbca-hsm-ejbca-patches ${EJBCA_PATCHES_TAG} (EJBCA ${EJBCA_VERSION}) -> ${EJBCA_HOME}"
    printf "  %-22s %s\n" "Database:"      "${DB_NAME} (user ${DB_USER}) - must not exist yet"
    printf "  %-22s %s\n" "Hostname:"      "${EJBCA_HOSTNAME}"
    printf "  %-22s %s\n" "Ports:"         "HTTP ${HTTP_PORT} / HTTPS ${HTTPS_PORT}"
    printf "  %-22s %s\n" "HSM library:"   "${P11_LIB_FILE}"
    if [[ ${#ADDONS[@]} -gt 0 ]]; then
        local a
        for a in "${ADDONS[@]}"; do
            printf "  %-22s %s\n" "Add-on:" "${a}  (pre-deploy before build, verify at the end)"
        done
    else
        printf "  %-22s %s\n" "Add-ons:" "(none)"
    fi
    echo -e "${BOLD}======================================================${NC}"
    echo ""
    if ! $ASSUME_YES; then
        read -r -p "Proceed with this plan? [y/N] " ans
        [[ "${ans,,}" == "y" || "${ans,,}" == "yes" ]] || { info "Aborted."; exit 0; }
    fi
}

# ---------------------------------------------------------------------------
# PHASE 2 - BUNDLE
# ---------------------------------------------------------------------------
phase2_bundle() {
    section "=== Phase 2: Verifying offline bundle ==="
    [[ -f "${BUNDLE_DIR}/SHA256SUMS" ]] || error "No SHA256SUMS in ${BUNDLE_DIR}."
    ( cd "${BUNDLE_DIR}" && sha256sum --quiet -c SHA256SUMS ) \
        || error "Bundle checksum verification failed (see lines above)."
    local f
    for f in "${BUNDLE_DIR}/os/Packages.gz" "${WILDFLY_ZIP}" "${MARIADB_JDBC_FILE}" "${EJBCA_ARCHIVE}"; do
        [[ -f "$f" ]] || error "Missing from bundle: ${f}"
    done
    info "Bundle verified."
}

# ---------------------------------------------------------------------------
# PHASE 3 - PRE-FLIGHT
# ---------------------------------------------------------------------------
phase3_preflight() {
    section "=== Phase 3: Pre-flight checks ==="
    # shellcheck disable=SC1091
    . /etc/os-release
    if [[ "${ID:-}" != "ubuntu" || "${VERSION_ID:-}" != "22.04" ]]; then
        warn "Tested on Ubuntu 22.04; this host is ${PRETTY_NAME:-unknown}."
    fi
    [[ ! -e "${WILDFLY_INSTALL_DIR}" ]] || error "${WILDFLY_INSTALL_DIR} already exists - mode fresh needs a clean host (see workbook: resetting a test host)."
    [[ ! -e "${WILDFLY_HOME}" ]]        || error "${WILDFLY_HOME} already exists - mode fresh needs a clean host."
    [[ ! -e "${EJBCA_HOME}" ]]          || error "${EJBCA_HOME} already exists - mode fresh needs a clean host."
    [[ -f "${P11_LIB_FILE}" ]]          || error "HSM library not found: ${P11_LIB_FILE} (install the Utimaco PKCS#11 library first)."
    info "Pre-flight checks passed."
}

# ---------------------------------------------------------------------------
# PHASE 4 - PACKAGES (local apt repository from the bundle)
# ---------------------------------------------------------------------------
phase4_packages() {
    section "=== Phase 4: Installing OS packages from the bundle ==="
    local list="/etc/apt/sources.list.d/ejbca-bundle.list"
    echo "deb [trusted=yes] file:${BUNDLE_DIR}/os ./" > "${list}"
    # Only the bundle repository is used, so stale online package lists can't interfere.
    local apt_opts=(-o "Dir::Etc::sourcelist=${list}" -o "Dir::Etc::sourceparts=-" -o "APT::Get::List-Cleanup=0")
    apt-get "${apt_opts[@]}" update -qq
    # shellcheck disable=SC2086
    DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" install -y -qq ${OS_PACKAGES}

    local jpath="/usr/lib/jvm/java-${JAVA_MAJOR}-openjdk-amd64/bin/java"
    [[ -x "$jpath" ]] || error "Java ${JAVA_MAJOR} binary not found at ${jpath}."
    update-alternatives --set java "$jpath" >/dev/null
    JAVA_HOME=$(dirname "$(dirname "$(readlink -f "$jpath")")")
    export JAVA_HOME
    info "Java: $(java -version 2>&1 | head -1) at ${JAVA_HOME}."
    info "Ant:  $(ant -version 2>&1 | head -1)."
}

# ---------------------------------------------------------------------------
# PHASE 5 - DATABASE
# ---------------------------------------------------------------------------
phase5_database() {
    section "=== Phase 5: Configuring MariaDB ==="
    systemctl enable --now mariadb

    # Secure root on a freshly installed MariaDB (fails harmlessly if already set).
    mysql -u root 2>/dev/null <<SQL || true
ALTER USER 'root'@'localhost' IDENTIFIED BY '${DB_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
    mysql_root -e "SELECT 1;" >/dev/null 2>&1 \
        || error "Cannot log in to MariaDB as root with DB_ROOT_PASS."

    local tables
    tables=$(mysql_root -sN -e "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='${DB_NAME}';")
    [[ "${tables}" -eq 0 ]] || error "Database '${DB_NAME}' already has ${tables} tables - mode fresh needs an empty database."

    mysql_root <<SQL
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL
    info "Database '${DB_NAME}' and user '${DB_USER}' ready."
}

# ---------------------------------------------------------------------------
# PHASE 6 - WILDFLY
# ---------------------------------------------------------------------------
phase6_wildfly() {
    section "=== Phase 6: Installing and configuring WildFly ${WILDFLY_VERSION} ==="
    unzip -q "${WILDFLY_ZIP}" -d /opt/
    ln -snf "${WILDFLY_INSTALL_DIR}" "${WILDFLY_HOME}"
    info "WildFly unpacked -> ${WILDFLY_INSTALL_DIR} (link ${WILDFLY_HOME})."

    # Remove RESTEasy-Crypto to avoid Bouncy Castle version conflicts.
    local module_xml="${WILDFLY_HOME}/modules/system/layers/base/org/jboss/as/jaxrs/main/module.xml"
    [[ -f "$module_xml" ]] || error "Expected ${module_xml} not found - unsupported WildFly layout."
    sed -i '/.*org.jboss.resteasy.resteasy-crypto.*/d' "$module_xml"
    rm -rf "${WILDFLY_HOME}/modules/system/layers/base/org/jboss/resteasy/resteasy-crypto/"
    info "RESTEasy-Crypto removed."

    # ---- standalone.conf (POSIX sh: sourced by standalone.sh) ----
    local tx_node_id
    tx_node_id=$(od -A n -t d -N 1 /dev/urandom | tr -d ' ')
    cat > "${WILDFLY_HOME}/bin/standalone.conf" <<EOF
if [ "x\$JBOSS_MODULES_SYSTEM_PKGS" = "x" ]; then
     JBOSS_MODULES_SYSTEM_PKGS="org.jboss.byteman"
fi

if [ "x\$JAVA_OPTS" = "x" ]; then
     JAVA_OPTS="-Xms${HEAP_SIZE_MB}m -Xmx${HEAP_SIZE_MB}m"
     JAVA_OPTS="\$JAVA_OPTS -Dhttps.protocols=TLSv1.2,TLSv1.3"
     JAVA_OPTS="\$JAVA_OPTS -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3"
     JAVA_OPTS="\$JAVA_OPTS -Djava.net.preferIPv4Stack=true"
     JAVA_OPTS="\$JAVA_OPTS -Djboss.modules.system.pkgs=\$JBOSS_MODULES_SYSTEM_PKGS"
     JAVA_OPTS="\$JAVA_OPTS -Djava.awt.headless=true"
     JAVA_OPTS="\$JAVA_OPTS -Djboss.tx.node.id=${tx_node_id}"
     JAVA_OPTS="\$JAVA_OPTS -XX:+HeapDumpOnOutOfMemoryError"
     JAVA_OPTS="\$JAVA_OPTS -Djdk.tls.ephemeralDHKeySize=2048"
else
     echo "JAVA_OPTS already set in environment; using: \$JAVA_OPTS"
fi

# PKCS#11 (SunPKCS11 internals) access for EJBCA and the HSM add-ons on Java 17+.
JAVA_OPTS="\$JAVA_OPTS --add-exports=jdk.crypto.cryptoki/sun.security.pkcs11.wrapper=ALL-UNNAMED"
EOF
    info "standalone.conf written (heap=${HEAP_SIZE_MB}MB, tx-node=${tx_node_id})."

    # ---- systemd service ----
    mkdir -p /etc/sysconfig
    cp "${WILDFLY_HOME}/bin/systemd/wildfly-standalone.service" /etc/systemd/system/
    cat > /etc/sysconfig/wildfly-standalone.conf <<EOF
# WildFly standalone service environment - generated by install-ejbca.sh
WILDFLY_HOME="${WILDFLY_INSTALL_DIR}"
JAVA_HOME="${JAVA_HOME}"
# Must be set (even to false): launch.sh tests it and /bin/sh is dash on Ubuntu.
WILDFLY_SYSTEMD_DEBUG="false"
EOF
    # launch.sh uses '==' inside [ ] (a bashism); Ubuntu's /bin/sh (dash) needs '='.
    local launch_sh="${WILDFLY_HOME}/bin/systemd/launch.sh"
    [[ -f "$launch_sh" ]] || error "${launch_sh} not found - unsupported WildFly layout."
    sed -i 's/==/=/g' "$launch_sh"

    systemctl daemon-reload
    id "${WILDFLY_USER}" &>/dev/null || useradd -r -s /bin/false "${WILDFLY_USER}"
    chown -R "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_INSTALL_DIR}/"

    systemctl start "${WILDFLY_SERVICE}"
    wait_for_wildfly

    # ---- Elytron credential store ----
    local pass_script="/usr/bin/wildfly_pass"
    printf '#!/bin/sh\necho '"'"'%s'"'"'\n' "$(openssl rand -base64 24)" > "$pass_script"
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "$pass_script"
    chmod 700 "$pass_script"
    mkdir -p "${WILDFLY_HOME}/standalone/configuration/keystore"
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/standalone/configuration/keystore"
    cli "/subsystem=elytron/credential-store=defaultCS:add(\
path=keystore/credentials,\
relative-to=jboss.server.config.dir,\
credential-reference={clear-text=\"{EXT}${pass_script}\", type=\"COMMAND\"},\
create=true)"

    # ---- MariaDB JDBC driver (hot-deploy, from the bundle) ----
    cp "${MARIADB_JDBC_FILE}" "${WILDFLY_HOME}/standalone/deployments/"
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/standalone/deployments/${MARIADB_JDBC_JAR}"
    info "Waiting for JDBC driver hot-deployment (8s)..."
    sleep 8

    # ---- Datasource ----
    cli "/subsystem=elytron/credential-store=defaultCS:add-alias(alias=dbPassword, secret-value=\"${DB_PASS}\")"
    cli "data-source add \
--name=ejbcads \
--connection-url=\"jdbc:mariadb://127.0.0.1:3306/${DB_NAME}\" \
--jndi-name=\"java:/EjbcaDS\" \
--use-ccm=true \
--driver-name=\"${MARIADB_JDBC_JAR}\" \
--driver-class=\"org.mariadb.jdbc.Driver\" \
--user-name=\"${DB_USER}\" \
--credential-reference={store=defaultCS, alias=dbPassword} \
--validate-on-match=true \
--background-validation=false \
--prepared-statements-cache-size=50 \
--share-prepared-statements=true \
--min-pool-size=5 \
--max-pool-size=150 \
--pool-prefill=true \
--transaction-isolation=TRANSACTION_READ_COMMITTED \
--check-valid-connection-sql=\"select 1;\""
    cli_reload

    # ---- Remoting on port 4447 (required by the EJBCA CLI) ----
    cli '/subsystem=remoting/http-connector=http-remoting-connector:write-attribute(name=connector-ref,value=remoting)'
    cli '/socket-binding-group=standard-sockets/socket-binding=remoting:add(port=4447,interface=management)'
    cli '/subsystem=undertow/server=default-server/http-listener=remoting:add(socket-binding=remoting,enable-http2=true)'
    cli_reload

    # ---- WildFly 38+: remove file passivation store of the web session cache (standalone) ----
    if [[ "${WILDFLY_MAJOR}" -ge 38 ]]; then
        cli '/subsystem=infinispan/cache-container=web/local-cache=passivation/store=file:remove' 2>/dev/null || true
        cli_reload
    fi

    # ---- Logging ----
    cli '/subsystem=logging/logger=org.ejbca:add(level=INFO)'
    cli '/subsystem=logging/logger=org.cesecore:add(level=INFO)'
    cli '/subsystem=logging/logger=com.keyfactor:add(level=INFO)'
    cli '/subsystem=undertow/server=default-server/host=default-host/setting=access-log:add(pattern="%h %t \"%r\" %s \"%{i,User-Agent}\"",relative-to=jboss.server.log.dir,directory=access-logs)'
    cli '/subsystem=logging/logger=io.undertow.accesslog:add(level=INFO)'

    # ---- Replace default HTTP/HTTPS listeners ----
    cli '/subsystem=undertow/server=default-server/http-listener=default:remove()'
    cli '/socket-binding-group=standard-sockets/socket-binding=http:remove()'
    cli '/subsystem=undertow/server=default-server/https-listener=https:remove()'
    cli '/socket-binding-group=standard-sockets/socket-binding=https:remove()'
    cli_reload

    # ---- 2-port separation: HTTP / HTTPS (optional client certificate) ----
    cli '/interface=http:add(inet-address="0.0.0.0")'
    cli '/interface=https:add(inet-address="0.0.0.0")'
    cli "/socket-binding-group=standard-sockets/socket-binding=http:add(port=\"${HTTP_PORT}\",interface=\"http\")"
    cli "/socket-binding-group=standard-sockets/socket-binding=https:add(port=\"${HTTPS_PORT}\",interface=\"https\")"
    cli "/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsKeystorePassword, secret-value=\"${KS_PASS}\")"
    cli "/subsystem=elytron/credential-store=defaultCS:add-alias(alias=httpsTruststorePassword, secret-value=\"${TS_PASS}\")"
    cli '/subsystem=elytron/key-store=httpsKS:add(path="keystore/keystore.p12",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsKeystorePassword},type=PKCS12)'
    cli '/subsystem=elytron/key-store=httpsTS:add(path="keystore/truststore.p12",relative-to=jboss.server.config.dir,credential-reference={store=defaultCS, alias=httpsTruststorePassword},type=PKCS12)'
    cli '/subsystem=elytron/key-manager=httpsKM:add(key-store=httpsKS,algorithm="SunX509",credential-reference={store=defaultCS, alias=httpsKeystorePassword})'
    cli '/subsystem=elytron/trust-manager=httpsTM:add(key-store=httpsTS)'

    local cipher_filter="TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,\
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,\
TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,\
TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,\
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,\
TLS_RSA_WITH_AES_256_CBC_SHA256,\
TLS_RSA_WITH_AES_256_CBC_SHA,\
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,\
TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,\
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,\
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,\
TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,\
TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"
    local tls13_suites="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
    cli "/subsystem=elytron/server-ssl-context=https:add(\
key-manager=httpsKM,\
protocols=[\"TLSv1.3\",\"TLSv1.2\"],\
use-cipher-suites-order=false,\
cipher-suite-filter=\"${cipher_filter}\",\
cipher-suite-names=\"${tls13_suites}\",\
trust-manager=httpsTM,\
want-client-auth=true,\
authentication-optional=true)"
    cli '/subsystem=undertow/server=default-server/http-listener=http:add(socket-binding="http", redirect-socket="https")'
    cli '/subsystem=undertow/server=default-server/https-listener=https:add(socket-binding="https", ssl-context="https", max-parameters=2048)'
    cli_reload

    # ---- HTTP protocol settings (OCSP GET, WSDL, encoded characters) ----
    cli '/system-property=org.apache.catalina.connector.URI_ENCODING:add(value="UTF-8")'
    cli '/system-property=org.apache.catalina.connector.USE_BODY_ENCODING_FOR_QUERY_STRING:add(value=true)'
    cli '/system-property=org.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH:add(value=true)'
    cli '/system-property=org.apache.tomcat.util.http.Parameters.MAX_COUNT:add(value=2048)'
    cli '/system-property=org.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH:add(value=true)'
    cli '/subsystem=webservices:write-attribute(name=wsdl-host, value=jbossws.undefined.host)'
    cli '/subsystem=webservices:write-attribute(name=modify-wsdl-address, value=true)'
    cli_reload

    # ---- Remove defaults EJBCA does not use (absent in some WildFly layouts) ----
    cli '/subsystem=ee/service=default-bindings:remove()' 2>/dev/null || true
    cli 'data-source remove --name=ExampleDS'             2>/dev/null || true
    cli '/socket-binding-group=standard-sockets/socket-binding=ajp:remove()' 2>/dev/null || true
    cli_reload

    cli ':take-snapshot(name="Pre-EJBCA WildFly configuration")'
    info "WildFly configuration complete."
}

# ---------------------------------------------------------------------------
# PHASE 7 - EJBCA SOURCE
# ---------------------------------------------------------------------------
phase7_ejbca_source() {
    section "=== Phase 7: Unpacking EJBCA source (${EJBCA_PATCHES_TAG}) ==="
    mkdir -p "${EJBCA_HOME}"
    # GitHub tag archives have one top-level directory; strip it.
    tar -xzf "${EJBCA_ARCHIVE}" --strip-components=1 -C "${EJBCA_HOME}"
    chmod -R u+rwX,go+rX "${EJBCA_HOME}"

    local found
    found=$(grep '^app.version.number=' "${EJBCA_HOME}/src/internal.properties" | cut -d= -f2 | tr -d ' \r')
    [[ "$found" == "$EJBCA_VERSION" ]] \
        || error "EJBCA source is version '${found}', config expects '${EJBCA_VERSION}'."
    info "EJBCA source ${found} unpacked -> ${EJBCA_HOME}."

    if grep -q 'ejbca.jboss-ds.xml' "${EJBCA_HOME}/build.xml"; then
        info "Add-on plugin hook present in build.xml."
    elif [[ ${#ADDONS[@]} -gt 0 ]]; then
        error "build.xml has no add-on plugin hook - this is not a DeviseFutures fork tag with the hook, add-ons cannot be built in."
    fi
}

# ---------------------------------------------------------------------------
# PHASE 8 - EJBCA CONFIGURATION FILES
# ---------------------------------------------------------------------------
phase8_ejbca_conf() {
    section "=== Phase 8: Writing EJBCA configuration files ==="
    local conf="${EJBCA_HOME}/conf"

    cp "${conf}/database.properties.sample" "${conf}/database.properties"
    cat >> "${conf}/database.properties" <<EOF

# --- Added by install-ejbca.sh ---
database.name=mysql
datasource.jndi-name=EjbcaDS
EOF

    cp "${conf}/cesecore.properties.sample" "${conf}/cesecore.properties"
    cat >> "${conf}/cesecore.properties" <<EOF

# --- Added by install-ejbca.sh ---
# Must stay the same for the whole life of this instance (and its backups).
password.encryption.key=${PBE_ENCRYPTION_KEY}
EOF

    cp "${conf}/web.properties.sample" "${conf}/web.properties"
    cat >> "${conf}/web.properties" <<EOF

# --- Added by install-ejbca.sh ---
httpsserver.hostname=${EJBCA_HOSTNAME}
httpsserver.dn=CN=${EJBCA_HOSTNAME},${DN_SUFFIX}
httpsserver.an=dnsName=${EJBCA_HOSTNAME}
httpsserver.password=${KS_PASS}
httpsserver.tokentype=P12
java.trustpassword=${TS_PASS}
superadmin.password=${SUPERADMIN_PASS}
superadmin.cn=SuperAdmin
superadmin.dn=CN=SuperAdmin,${DN_SUFFIX}
superadmin.batch=true
httpserver.pubhttp=${HTTP_PORT}
httpserver.privhttps=${HTTPS_PORT}
httpserver.pubhttps=${HTTPS_PORT}
cryptotoken.p11.lib.1.name=${P11_LIB_NAME}
cryptotoken.p11.lib.1.file=${P11_LIB_FILE}
EOF

    cp "${conf}/install.properties.sample" "${conf}/install.properties"
    cat >> "${conf}/install.properties" <<EOF

# --- Added by install-ejbca.sh ---
ca.name=ManagementCA
ca.dn=CN=ManagementCA,${DN_SUFFIX}
ca.keytype=RSA
ca.keyspec=4096
ca.signaturealgorithm=SHA256WithRSA
ca.validity=3650
ca.tokentype=soft
ca.tokenpassword=null
ca.policy=null
ca.certificateprofile=ROOTCA
EOF

    cp "${conf}/ejbca.properties.sample" "${conf}/ejbca.properties"
    cat >> "${conf}/ejbca.properties" <<EOF

# --- Added by install-ejbca.sh ---
healthcheck.catokensigntest=true
EOF
    chmod 600 "${conf}"/*.properties
    info "EJBCA configuration files written."
}

# ---------------------------------------------------------------------------
# PHASE 9 / 12 - ADD-ON HOOKS
# ---------------------------------------------------------------------------
run_addons() {
    local mode="$1" a
    [[ ${#ADDONS[@]} -gt 0 ]] || { info "No add-ons requested."; return 0; }
    for a in "${ADDONS[@]}"; do
        info "Running: ${a} --config ${CONFIG} --mode ${mode} --yes"
        "$a" --config "${CONFIG}" --mode "${mode}" --yes \
            || error "Add-on ${a} failed in mode ${mode}."
    done
}

phase9_addons_predeploy() {
    section "=== Phase 9: Add-ons - pre-deploy ==="
    run_addons pre-deploy
}

# ---------------------------------------------------------------------------
# PHASE 10 - BUILD & DEPLOY
# ---------------------------------------------------------------------------
health_url() { echo "http://localhost:${HTTP_PORT}/ejbca/publicweb/healthcheck/ejbcahealth"; }

phase10_build_deploy() {
    section "=== Phase 10: Building and deploying EJBCA ==="
    export APPSRV_HOME="${WILDFLY_HOME}"
    export JAVA_HOME
    ( cd "${EJBCA_HOME}" && ant -q clean deployear ) || error "ant clean deployear failed."

    # ALLOK alone is not enough: during redeploy the old instance may still answer.
    # Wait for the endpoint to go down, then up, then for the EJBCA tables.
    local i=0
    sleep 5
    while curl -s --max-time 2 "$(health_url)" 2>/dev/null | grep -q "^ALLOK"; do
        sleep 3; i=$((i+3)); [[ $i -ge 60 ]] && break
    done
    local j=0
    until curl -s --max-time 3 "$(health_url)" 2>/dev/null | grep -q "^ALLOK"; do
        sleep 5; j=$((j+5))
        [[ $j -ge 300 ]] && error "EJBCA health endpoint not ALLOK after 300s. Check: ${WILDFLY_HOME}/standalone/log/server.log"
        info "  Still initialising... (${j}s)"
    done
    local k=0
    until mysql -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -e "SELECT 1 FROM CAData LIMIT 1;" &>/dev/null; do
        sleep 5; k=$((k+1)); [[ $k -ge 12 ]] && error "EJBCA tables not accessible after 60s."
    done
    sleep 5
    info "EJBCA is deployed and the database is ready."
}

# ---------------------------------------------------------------------------
# PHASE 11 - RUNINSTALL & KEYSTORES
# ---------------------------------------------------------------------------
phase11_runinstall() {
    section "=== Phase 11: EJBCA installation (ManagementCA, SuperAdmin, TLS) ==="
    export APPSRV_HOME="${WILDFLY_HOME}"
    export JAVA_HOME
    ( cd "${EJBCA_HOME}" && ant runinstall ) || error "ant runinstall failed."

    local cert_count
    cert_count=$(mysql -u"${DB_USER}" -p"${DB_PASS}" "${DB_NAME}" -sN \
        -e "SELECT COUNT(*) FROM CertificateData WHERE username='superadmin';" 2>/dev/null || echo 0)
    [[ "${cert_count}" -ge 1 ]] || error "ant runinstall finished but the SuperAdmin certificate is not in the database (EJBCA was not ready). Reset the host and run again."
    info "SuperAdmin certificate stored in the database."

    ( cd "${EJBCA_HOME}" && ant deploy-keystore ) || error "ant deploy-keystore failed."
    chown "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_HOME}/standalone/configuration/keystore/"*.p12
    cli_reload
    info "TLS keystores deployed."
}

phase12_addons_verify() {
    section "=== Phase 12: Add-ons - verify ==="
    run_addons verify
}

# ---------------------------------------------------------------------------
# PHASE 13 - FINALISE
# ---------------------------------------------------------------------------
phase13_finalise() {
    section "=== Phase 13: Finalising ==="
    chown -R "${WILDFLY_USER}:${WILDFLY_USER}" "${WILDFLY_INSTALL_DIR}/"
    chown -R root:root "${EJBCA_HOME}/"
    systemctl enable "${WILDFLY_SERVICE}"

    if ufw status 2>/dev/null | grep -q "Status: active"; then
        ufw allow "${HTTP_PORT}/tcp"  comment "EJBCA HTTP"
        ufw allow "${HTTPS_PORT}/tcp" comment "EJBCA HTTPS"
        info "UFW rules added for ports ${HTTP_PORT} and ${HTTPS_PORT}."
    else
        warn "UFW is not active. Make sure ports ${HTTP_PORT} and ${HTTPS_PORT} are reachable."
    fi

    echo ""
    echo -e "${BOLD}${GREEN}======================================================${NC}"
    echo -e "${BOLD}${GREEN}  EJBCA ${EJBCA_VERSION} (${EJBCA_PATCHES_TAG}) - installation complete${NC}"
    echo -e "${BOLD}${GREEN}======================================================${NC}"
    printf "  %-20s %s\n" "SuperAdmin P12:" "${EJBCA_HOME}/p12/superadmin.p12"
    printf "  %-20s %s\n" "Admin UI:"       "https://${EJBCA_HOSTNAME}:${HTTPS_PORT}/ejbca/adminweb/"
    printf "  %-20s %s\n" "WildFly log:"    "${WILDFLY_HOME}/standalone/log/server.log"
    echo ""
    echo "  Next: copy superadmin.p12 to your workstation and import it in the browser"
    echo "        (password: SUPERADMIN_PASS from the config file)."
    echo -e "${BOLD}${GREEN}======================================================${NC}"
}

# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------
main() {
    [[ $EUID -eq 0 ]] || error "Run as root (sudo)."
    parse_args "$@"
    phase1_plan
    phase2_bundle
    phase3_preflight
    phase4_packages
    phase5_database
    phase6_wildfly
    phase7_ejbca_source
    phase8_ejbca_conf
    phase9_addons_predeploy
    phase10_build_deploy
    phase11_runinstall
    phase12_addons_verify
    phase13_finalise
}

main "$@"
