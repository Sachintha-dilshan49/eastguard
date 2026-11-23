#!/usr/bin/env bash
# Generates the EastGuard demo PKI and lease-signing key with JDK keytool only.
# Run from anywhere: ./scripts/gen-certs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="$ROOT/keys"
VALIDITY_DAYS=365
TEST_FIXTURES=false
FORCE=false
ADD_COMPONENT=""
ADD_CONTROL_SIGNER=false
ADD_CONSOLE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -OutDir|--out-dir)
            OUT_DIR="$2"
            shift 2
            ;;
        -ValidityDays|--validity-days)
            VALIDITY_DAYS="$2"
            shift 2
            ;;
        -TestFixtures|--test-fixtures)
            TEST_FIXTURES=true
            shift
            ;;
        -Force|--force)
            FORCE=true
            shift
            ;;
        -AddComponent|--add-component)
            ADD_COMPONENT="$2"
            shift 2
            ;;
        -AddControlSigner|--add-control-signer)
            ADD_CONTROL_SIGNER=true
            shift
            ;;
        -AddConsole|--add-console)
            ADD_CONSOLE=true
            shift
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 2
            ;;
    esac
done

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"
CA_DIR="$OUT_DIR/ca"
WORK_DIR="$OUT_DIR/.work"

find_keytool() {
    if [[ -n "${JAVA_HOME:-}" && -x "$JAVA_HOME/bin/keytool" ]]; then
        echo "$JAVA_HOME/bin/keytool"
        return
    fi
    if command -v keytool >/dev/null 2>&1; then
        command -v keytool
        return
    fi
    if command -v java >/dev/null 2>&1; then
        local jh
        jh=$(java -XshowSettings:properties -version 2>&1 | grep 'java.home' | awk -F'=' '{print $2}' | tr -d ' \r\n')
        if [[ -n "$jh" && -x "$jh/bin/keytool" ]]; then
            echo "$jh/bin/keytool"
            return
        fi
    fi
    echo "keytool not found: set JAVA_HOME to a JDK 21+ installation" >&2
    exit 1
}

KEYTOOL="$(find_keytool)"

get_secret() {
    local env_name="$1"
    local file="$2"
    if [[ -n "${!env_name:-}" ]]; then
        echo "${!env_name}"
        return
    fi
    if [[ -f "$file" ]]; then
        local v
        v="$(head -n 1 "$file" | tr -d '\r\n')"
        if [[ ${#v} -ge 8 ]]; then
            echo "$v"
            return
        fi
        echo "password file $file is shorter than 8 characters" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$file")"
    local secret
    secret=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\r\n')
    printf "%s" "$secret" > "$file"
    chmod 600 "$file" 2>/dev/null || true
    echo "$secret"
}

cleanup() {
    rm -rf "$WORK_DIR"
    unset EG_GEN_STORE EG_GEN_SIGNER EG_GEN_CONTROL EG_GEN_CA
}
trap cleanup EXIT

new_ca() {
    local store="$1"
    local dname="$2"
    local cer_out="$3"
    "$KEYTOOL" -genkeypair -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_CA -keypass:env EG_GEN_CA \
        -alias ca -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
        -dname "$dname" -validity "$((VALIDITY_DAYS + 30))" \
        -ext "bc:c=ca:true,pathlen:0" -ext "ku:c=keyCertSign,cRLSign"
    "$KEYTOOL" -exportcert -rfc -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_CA -alias ca -file "$cer_out"
    chmod 600 "$store" 2>/dev/null || true
}

new_leaf() {
    local name="$1"
    local dname="$2"
    local ca_store="$3"
    local ca_cer="$4"
    shift 4
    local -a exts=("$@")

    local store="$OUT_DIR/$name.p12"
    local csr="$WORK_DIR/$name.csr"
    local cer="$WORK_DIR/$name.cer"

    "$KEYTOOL" -genkeypair -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_STORE -keypass:env EG_GEN_STORE \
        -alias "$name" -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
        -dname "$dname" -validity 1

    "$KEYTOOL" -certreq -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_STORE -alias "$name" -file "$csr"

    local -a gencert_args=(
        -gencert -rfc -storetype PKCS12 -keystore "$ca_store" \
        -storepass:env EG_GEN_CA -alias ca -infile "$csr" -outfile "$cer" \
        -sigalg SHA256withECDSA -validity "$VALIDITY_DAYS" \
        -ext "ku:c=digitalSignature"
    )
    for ext in "${exts[@]}"; do
        gencert_args+=(-ext "$ext")
    done
    "$KEYTOOL" "${gencert_args[@]}"

    "$KEYTOOL" -importcert -noprompt -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_STORE -alias issuing-ca -file "$ca_cer"

    "$KEYTOOL" -importcert -noprompt -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_STORE -alias "$name" -file "$cer"

    "$KEYTOOL" -delete -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_STORE -alias issuing-ca

    chmod 600 "$store" 2>/dev/null || true
    echo "  $name.p12"
}

new_server() {
    local name="$1"
    local component="$2"
    new_leaf "$name" "CN=$name, O=EastGuard Demo" "$CA_STORE" "$CA_CER" \
        "san=dns:localhost,ip:127.0.0.1,uri:urn:eastguard:component:$component" \
        "eku=serverAuth,clientAuth"
}

new_workload() {
    local name="$1"
    local san="$2"
    local castore="$3"
    local cacer="$4"
    local cn="$5"
    local -a exts=("eku=clientAuth")
    if [[ -n "$san" ]]; then
        exts+=("san=$san")
    fi
    new_leaf "$name" "CN=$cn, O=EastGuard Demo" "$castore" "$cacer" "${exts[@]}"
}

new_console() {
    new_leaf "console" "CN=console, O=EastGuard Demo" "$CA_STORE" "$CA_CER" \
        "san=uri:urn:eastguard:console:dashboard" "eku=clientAuth"
}

new_control_signer() {
    local store="$OUT_DIR/control-signer.p12"
    local cer="$OUT_DIR/control-k1.cer"
    "$KEYTOOL" -genkeypair -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_CONTROL -keypass:env EG_GEN_CONTROL \
        -alias control-k1 -keyalg Ed25519 \
        -dname "CN=EastGuard control signer control-k1, O=EastGuard Demo" \
        -validity "$VALIDITY_DAYS"
    "$KEYTOOL" -exportcert -rfc -storetype PKCS12 -keystore "$store" \
        -storepass:env EG_GEN_CONTROL -alias control-k1 -file "$cer"
    chmod 600 "$store" 2>/dev/null || true
    echo "  control-signer.p12, control-k1.cer"
}

mkdir -p "$CA_DIR" "$WORK_DIR"
CA_STORE="$CA_DIR/ca.p12"
CA_CER="$OUT_DIR/ca.cer"

if [[ -n "$ADD_COMPONENT" ]]; then
    target="$OUT_DIR/$ADD_COMPONENT.p12"
    if [[ -f "$target" && "$FORCE" != true ]]; then
        echo "$target already exists (use -Force to replace it)" >&2
        exit 1
    fi
    rm -f "$target"
    export EG_GEN_STORE="$(get_secret EASTGUARD_STORE_PASS "$OUT_DIR/store.pass")"
    export EG_GEN_CA="$(get_secret EASTGUARD_CA_PASS "$CA_DIR/ca.pass")"
    new_server "$ADD_COMPONENT" "$ADD_COMPONENT"
    exit 0
fi

if [[ "$ADD_CONSOLE" == true ]]; then
    target="$OUT_DIR/console.p12"
    if [[ -f "$target" && "$FORCE" != true ]]; then
        echo "$target already exists (use -Force to replace it)" >&2
        exit 1
    fi
    rm -f "$target"
    export EG_GEN_STORE="$(get_secret EASTGUARD_STORE_PASS "$OUT_DIR/store.pass")"
    export EG_GEN_CA="$(get_secret EASTGUARD_CA_PASS "$CA_DIR/ca.pass")"
    new_console
    exit 0
fi

if [[ "$ADD_CONTROL_SIGNER" == true ]]; then
    export EG_GEN_CONTROL="$(get_secret EASTGUARD_CONTROL_SIGNER_PASS "$OUT_DIR/control-signer.pass")"
    new_control_signer
    exit 0
fi

if [[ "$FORCE" == true ]]; then
    rm -f "$OUT_DIR"/*.p12 "$OUT_DIR"/*.cer "$CA_DIR"/*.p12 "$CA_DIR"/*.cer
fi

export EG_GEN_STORE="$(get_secret EASTGUARD_STORE_PASS "$OUT_DIR/store.pass")"
export EG_GEN_SIGNER="$(get_secret EASTGUARD_SIGNER_PASS "$OUT_DIR/signer.pass")"
export EG_GEN_CONTROL="$(get_secret EASTGUARD_CONTROL_SIGNER_PASS "$OUT_DIR/control-signer.pass")"
export EG_GEN_CA="$(get_secret EASTGUARD_CA_PASS "$CA_DIR/ca.pass")"

echo "keytool: $KEYTOOL"
echo "writing to $OUT_DIR"

new_ca "$CA_STORE" "CN=EastGuard Demo CA, O=EastGuard Demo" "$CA_CER"
"$KEYTOOL" -importcert -noprompt -storetype PKCS12 -keystore "$OUT_DIR/truststore.p12" \
    -storepass:env EG_GEN_STORE -alias eastguard-demo-ca -file "$CA_CER"
chmod 600 "$OUT_DIR/truststore.p12" 2>/dev/null || true
echo "  ca/ca.p12, ca.cer, truststore.p12"

bad_store="$CA_DIR/untrusted-ca.p12"
bad_cer="$WORK_DIR/untrusted-ca.cer"
new_ca "$bad_store" "CN=Untrusted CA, O=Not EastGuard" "$bad_cer"
echo "  ca/untrusted-ca.p12"

new_server "tokensvc" "tokensvc"
new_server "gateway-app-02" "gateway-app-02"
new_server "gateway-app-03" "gateway-app-03"
new_server "control" "control"
new_server "detector" "detector"

new_workload "workload-web-01" "uri:urn:eastguard:workload:web-01" "$CA_STORE" "$CA_CER" "web-01"
new_workload "workload-api-01" "uri:urn:eastguard:workload:api-01" "$CA_STORE" "$CA_CER" "api-01"
new_workload "untrusted-web-01" "uri:urn:eastguard:workload:web-01" "$bad_store" "$bad_cer" "web-01"
new_console

if [[ "$TEST_FIXTURES" == true ]]; then
    new_workload "workload-nosan" "" "$CA_STORE" "$CA_CER" "web-01"
    new_workload "workload-twosan" "uri:urn:eastguard:workload:web-01,uri:urn:eastguard:workload:api-01" \
        "$CA_STORE" "$CA_CER" "web-01"
fi

signer="$OUT_DIR/lease-signer.p12"
"$KEYTOOL" -genkeypair -storetype PKCS12 -keystore "$signer" \
    -storepass:env EG_GEN_SIGNER -keypass:env EG_GEN_SIGNER \
    -alias lease-k1 -keyalg Ed25519 \
    -dname "CN=EastGuard lease signer lease-k1, O=EastGuard Demo" \
    -validity "$VALIDITY_DAYS"
"$KEYTOOL" -exportcert -rfc -storetype PKCS12 -keystore "$signer" \
    -storepass:env EG_GEN_SIGNER -alias lease-k1 -file "$OUT_DIR/lease-k1.cer"
chmod 600 "$signer" 2>/dev/null || true
echo "  lease-signer.p12, lease-k1.cer"

new_control_signer
echo "done"

