#!/bin/bash
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
BLUE='\033[94m'
CYAN='\033[96m'
WHITE='\033[97m'
BOLD='\033[1m'
DIM='\033[2m'
MAGENTA='\033[95m'
END='\033[0m'

# --- Variabel Global ---
OUTPUT_DIR="./security_results"
VULNERABILITIES=()
RESULTS=()
LOGS=()
TOTAL_CHECKS=0
VULNERABLE_COUNT=0
SECURE_COUNT=0
SPINNER_PID=0

# --- Fungsi Penanganan Sinyal ---
function cleanup_and_exit() {
    echo -e "\n\n${YELLOW}⚠ Pengujian dihentikan oleh pengguna${END}"
    stop_spinner
    print_summary
    exit 0
}

# Tangkap sinyal SIGINT (Ctrl+C)
trap cleanup_and_exit SIGINT

# --- Fungsi Animasi ---
function elegant_spinner() {
    local text="$1"
    local frames=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    while true; do
        for frame in "${frames[@]}"; do
            echo -ne "\r${CYAN}${frame} ${text}${END}"
            sleep 0.08
        done
    done
}

function start_spinner() {
    elegant_spinner "$1" &
    SPINNER_PID=$!
    # Sembunyikan kursor
    tput civis
}

function stop_spinner() {
    if [[ $SPINNER_PID -ne 0 ]]; then
        kill "$SPINNER_PID" 2>/dev/null
        wait "$SPINNER_PID" 2>/dev/null
    fi
    SPINNER_PID=0
    # Hapus baris spinner dan kembalikan kursor
    echo -ne "\r" && tput cnorm && tput el
}

# --- Fungsi Inti ---
function print_banner() {
clear
}

function run_command() {
    local cmd="$1"
    local timeout_duration="${2:-60}"
    local output
    
    # Log perintah
    echo -e "\n[COMMAND] $(date '+%H:%M:%S') - ${cmd}" >> "$LOG_FILE"

    # Jalankan perintah dengan timeout
    output=$(timeout "$timeout_duration" bash -c "$cmd" 2>&1)
    local return_code=$?

    # Log output
    echo -e "[STDOUT/STDERR]\n${output}\n[RETURNCODE] ${return_code}" >> "$LOG_FILE"
    
    # Kembalikan output untuk diproses
    echo "$output"
}

function check_item() {
    local description="$1"
    local is_vulnerable="$2" # "true" atau "false"
    local details="$3"
    
    ((TOTAL_CHECKS++))
    local result_entry

    if [[ "$is_vulnerable" == "true" ]]; then
        ((VULNERABLE_COUNT++))
        echo -e "${RED}✗ VULNERABLE${END} ${WHITE}${description}${END}"
        if [[ -n "$details" ]]; then
            echo -e "  ${DIM}└─ ${details}${END}"
            VULNERABILITIES+=("${description}: ${details}")
        else
            VULNERABILITIES+=("${description}")
        fi
        result_entry="VULNERABLE|${description}|${details}"
    else
        ((SECURE_COUNT++))
        echo -e "${GREEN}✓ SECURE${END}     ${WHITE}${description}${END}"
        result_entry="SECURE|${description}|${details}"
    fi
    RESULTS+=("$result_entry")
}

# --- Fungsi Pengujian ---

function test_ssl_tls() {
    echo -e "\n${BLUE}▶ Testing for Weak Transport Layer Security & Testing for Padding Oracle${END}"
    echo -e "${DIM}────────────────────────────────────────${END}"

    local nmap_enum_cmd="nmap --script ssl-enum-ciphers -p ${PORT} ${HOST}"
    start_spinner "Enumerating SSL/TLS ciphers..."
    local nmap_enum_output=$(run_command "$nmap_enum_cmd")
    stop_spinner

    # Tes Protokol
    check_item "SSLv2 Protocol" "$(echo "$nmap_enum_output" | grep -qi 'sslv2'; echo $? | sed 's/0/true/g;s/1/false/g')" "Obsolete protocol with known vulnerabilities. Disable immediately."
    check_item "SSLv3 Protocol" "$(echo "$nmap_enum_output" | grep -qi 'sslv3'; echo $? | sed 's/0/true/g;s/1/false/g')" "Deprecated protocol vulnerable to POODLE attack. Disable immediately."
    check_item "TLSv1.0 Protocol" "$(echo "$nmap_enum_output" | grep -qi 'tls1.0'; echo $? | sed 's/0/true/g;s/1/false/g')" "Deprecated protocol with known weaknesses. Consider disabling."
    check_item "TLSv1.1 Protocol" "$(echo "$nmap_enum_output" | grep -qi 'tls1.1'; echo $? | sed 's/0/true/g;s/1/false/g')" "Deprecated protocol with known weaknesses. Consider disabling."
    
    # Tes Heartbleed
    start_spinner "Checking Heartbleed (CVE-2014-0160)..."
    local heartbleed_output=$(run_command "nmap --script ssl-heartbleed -p ${PORT} ${HOST}")
    stop_spinner
    check_item "Heartbleed (CVE-2014-0160)" "$(echo "$heartbleed_output" | grep -qi 'vulnerable'; echo $? | sed 's/0/true/g;s/1/false/g')" "Memory disclosure vulnerability. Patch OpenSSL immediately."
    
    # Tes Cipher Lemah
    start_spinner "Checking cipher strength..."
    local sslscan_output=$(run_command "sslscan --no-color ${HOST}:${PORT}")
    stop_spinner
    local weak_ciphers=$(echo "$sslscan_output" | grep 'Accepted' | grep -E 'RC4|DES|NULL|EXPORT|MD5|ANON|3DES')
    if [[ -n "$weak_ciphers" ]]; then
        check_item "Weak Ciphers" "true" "Weak ciphers accepted (e.g., RC4, 3DES). Disable them to improve cryptographic strength."
    else
        check_item "Weak Ciphers" "false" ""
    fi
    
    # Tes Validitas Sertifikat
    start_spinner "Checking certificate validity..."
    local cert_output=$(run_command "echo | openssl s_client -connect ${HOST}:${PORT} -servername ${HOST} 2>/dev/null | openssl x509 -noout -dates -subject")
    stop_spinner
    local not_after=$(echo "$cert_output" | grep 'notAfter=' | cut -d= -f2)
    local subject=$(echo "$cert_output" | grep 'subject=' | cut -d= -f2-)
    if [[ -n "$not_after" ]]; then
        local expiry_epoch=$(date -d "$not_after" +%s)
        local now_epoch=$(date +%s)
        if [[ $now_epoch -gt $expiry_epoch ]]; then
            check_item "Certificate Validity" "true" "Certificate for '${subject}' expired on ${not_after}."
        else
            check_item "Certificate Validity" "false" "Certificate for '${subject}' is valid until ${not_after}."
        fi
    else
        check_item "Certificate Validity" "true" "Could not retrieve certificate information."
    fi

    # Tes HSTS
    start_spinner "Checking HSTS header..."
    local hsts_header=$(run_command "curl -s -I ${TARGET_WITH_SCHEME}" | grep -i 'strict-transport-security')
    stop_spinner
    if [[ -n "$hsts_header" ]]; then
        local max_age=$(echo "$hsts_header" | grep -o -i 'max-age=[0-9]*' | cut -d= -f2)
        if [[ -n "$max_age" && "$max_age" -lt 31536000 ]]; then
            check_item "HSTS Header" "true" "HSTS max-age (${max_age}s) is too low. Recommended: >= 31536000."
        else
            check_item "HSTS Header" "false" "HSTS header is present and appears strong."
        fi
    else
        check_item "HSTS Header" "true" "HTTP Strict Transport Security (HSTS) header not implemented."
    fi

    # Tes TLS Renegotiation (Sudah tercakup di nmap_enum)
    check_item "TLS Renegotiation" "$(echo "$nmap_enum_output" | grep -qi 'renegotiation'; echo $? | sed 's/0/true/g;s/1/false/g')" "Server may be vulnerable to TLS renegotiation attacks."

    # Tes POODLE
    start_spinner "Testing for POODLE Attack..."
    local poodle_output=$(run_command "nmap -sV --script ssl-poodle -p ${PORT} ${HOST}")
    stop_spinner
    check_item "POODLE Attack" "$(echo "$poodle_output" | grep -qi 'vulnerable'; echo $? | sed 's/0/true/g;s/1/false/g')" "Padding Oracle On Downgraded Legacy Encryption. Disable SSLv3."
}

function test_http_security() {
    echo -e "\n${BLUE}▶ Testing for Sensitive Information Sent via Unencrypted Channels${END}"
    echo -e "${DIM}────────────────────────────────────────${END}"
    
    start_spinner "Fetching HTTP headers..."
    local headers_output=$(run_command "curl -s -I ${TARGET_WITH_SCHEME}")
    stop_spinner

    # Tes Header Keamanan
    check_item "X-Frame-Options Header" "$(echo "$headers_output" | grep -qvi 'X-Frame-Options'; echo $? | sed 's/0/true/g;s/1/false/g')" "Missing X-Frame-Options header (Clickjacking)."
    check_item "X-Content-Type-Options Header" "$(echo "$headers_output" | grep -qvi 'X-Content-Type-Options'; echo $? | sed 's/0/true/g;s/1/false/g')" "Missing X-Content-Type-Options header (MIME-sniffing)."
    check_item "Content-Security-Policy Header" "$(echo "$headers_output" | grep -qvi 'Content-Security-Policy'; echo $? | sed 's/0/true/g;s/1/false/g')" "Missing Content-Security-Policy header (XSS)."

    # Tes Pengungkapan Versi Server
    local server_header=$(echo "$headers_output" | grep -i 'Server:')
    if [[ -n "$server_header" && "$server_header" =~ [0-9]+\.[0-9]+ ]]; then
        check_item "Server Version Disclosure" "true" "Server version exposed: '${server_header#*:}'. This can help attackers."
    else
        check_item "Server Version Disclosure" "false" ""
    fi
    
    # Tes Redirect HTTP ke HTTPS
    if [[ "$SCHEME" == "https" ]]; then
        start_spinner "Testing for HTTP to HTTPS redirect..."
        local redirect_check=$(run_command "curl -s -I -L http://${HOST}" | grep -i 'Location: https://')
        stop_spinner
        if [[ -z "$redirect_check" ]]; then
            check_item "HTTP to HTTPS Redirect" "true" "HTTP traffic does not automatically redirect to HTTPS."
        else
            check_item "HTTP to HTTPS Redirect" "false" ""
        fi
    fi

    # Tes Konten Campuran (Mixed Content)
    if [[ "$SCHEME" == "https" ]]; then
        start_spinner "Checking for mixed content..."
        local page_content=$(run_command "curl -sL ${TARGET_WITH_SCHEME}" 30)
        stop_spinner
        if echo "$page_content" | grep -Eq 'src=["'\'']http://|href=["'\'']http://'; then
            check_item "Mixed Content (Insecure Resources)" "true" "HTTPS page loads insecure HTTP resources."
        else
            check_item "Mixed Content (Insecure Resources)" "false" ""
        fi
    fi
}

function test_weak_crypto() {
    echo -e "\n${BLUE}▶ Testing for Weak Encryption${END}"
    echo -e "${DIM}────────────────────────────────────────${END}"

    start_spinner "Fetching certificate details..."
    local cert_text=$(run_command "echo | openssl s_client -connect ${HOST}:${PORT} -servername ${HOST} 2>/dev/null | openssl x509 -noout -text")
    stop_spinner

    # Tes Panjang Kunci RSA
    local key_length=$(echo "$cert_text" | grep 'Public-Key:' | sed -e 's/.*(//' -e 's/ bit)//')
    if [[ -n "$key_length" && "$key_length" -lt 2048 ]]; then
        check_item "RSA Key Length" "true" "Key length is ${key_length} bits. Keys less than 2048 bits are considered weak."
    else
        check_item "RSA Key Length" "false" "Key length is ${key_length} bits (Secure)."
    fi

    # Tes Algoritma Tanda Tangan
    local sig_algo=$(echo "$cert_text" | grep 'Signature Algorithm:' | awk '{print $3}')
    if echo "$sig_algo" | grep -qi -e 'md5' -e 'sha1'; then
        check_item "Signature Algorithm" "true" "Uses weak hash algorithm: '${sig_algo}'. MD5/SHA1 are broken."
    else
        check_item "Signature Algorithm" "false" "Uses strong hash algorithm: '${sig_algo}'."
    fi
    
    # Tes Parameter DH
    start_spinner "Checking DH parameters..."
    local dh_params_output=$(run_command "nmap --script ssl-dh-params -p ${PORT} ${HOST}")
    stop_spinner
    if echo "$dh_params_output" | grep -qi -e 'weak' -e '1024 bits'; then
        check_item "Diffie-Hellman Parameters" "true" "Weak DH parameters detected (Logjam)."
    else
        check_item "Diffie-Hellman Parameters" "false" "Strong DH parameters detected."
    fi

    # Tes Perfect Forward Secrecy (PFS)
    start_spinner "Checking for Perfect Forward Secrecy (PFS)..."
    local pfs_check_output=$(run_command "sslscan --no-color ${HOST}:${PORT}")
    stop_spinner
    if echo "$pfs_check_output" | grep -qi -e 'ECDHE' -e 'DHE'; then
        check_item "Perfect Forward Secrecy (PFS)" "false" "PFS is supported (ECDHE/DHE ciphers found)."
    else
        check_item "Perfect Forward Secrecy (PFS)" "true" "PFS is not supported. Past communications are at risk if private key is compromised."
    fi
}

# --- Fungsi Laporan & Utilitas ---

function print_summary() {
    # Hentikan spinner jika masih berjalan
    stop_spinner

    echo -e "\n${CYAN}============================================================"
    echo -e "${BOLD}SECURITY TEST SUMMARY${END}"
    
    echo -e "Total Checks: ${WHITE}${TOTAL_CHECKS}${END}"
    echo -e "Secure: ${GREEN}${SECURE_COUNT}${END}"
    echo -e "Vulnerable: ${RED}${VULNERABLE_COUNT}${END}"
    
    if [[ $VULNERABLE_COUNT -gt 0 ]]; then
        echo -e "\n${RED}⚠ VULNERABILITIES FOUND:${END}"
        for vuln in "${VULNERABILITIES[@]}"; do
            echo -e "  ${RED}•${END} ${vuln}"
        done
    else
        echo -e "\n${GREEN}✓ No major vulnerabilities detected!${END}"
    fi

    # Simpan hasil ke file
    mkdir -p "$OUTPUT_DIR"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local report_file="${OUTPUT_DIR}/security_report_${timestamp}.txt"
    
    {
        echo "Security Test Report"
        echo "Target: ${TARGET}"
        echo "Date: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "======================================================================"
        echo ""
        echo "Summary:"
        echo "  Total Checks: ${TOTAL_CHECKS}"
        echo "  Secure: ${SECURE_COUNT}"
        echo "  Vulnerable: ${VULNERABLE_COUNT}"
        echo ""
        echo "Detailed Results:"
        echo "------------------"
        for result in "${RESULTS[@]}"; do
            IFS='|' read -r status desc details <<< "$result"
            printf "[%-10s] %s\n" "$status" "$desc"
            if [[ -n "$details" ]]; then
                printf "      Details: %s\n" "$details"
            fi
            echo ""
        done
        echo "======================================================================"
        echo "End of Report"
    } > "$report_file"

    echo -e "\n${DIM}Report saved: ${report_file}${END}"
    echo -e "${DIM}Command log saved: ${LOG_FILE}${END}"
    echo -e "${RED}Press ENTER to Complete Your Scanner${END}"
}

function parse_target() {
    local input="$1"
    
    # Ekstrak scheme
    if [[ "$input" =~ ^https:// ]]; then
        SCHEME="https"
    elif [[ "$input" =~ ^http:// ]]; then
        SCHEME="http"
    else
        # Default ke https jika tidak ada scheme
        SCHEME="https"
        input="https://${input}"
    fi
    TARGET_WITH_SCHEME="$input"

    # Hapus scheme untuk mendapatkan host dan port
    local domain_part="${input#*//}"
    
    # Pisahkan host dan port
    if [[ "$domain_part" == *":"* ]]; then
        HOST="${domain_part%:*}"
        PORT="${domain_part#*:}"
    else
        HOST="$domain_part"
        # Gunakan port default berdasarkan scheme
        if [[ "$SCHEME" == "https" ]]; then
            PORT="443"
        else
            PORT="80"
        fi
    fi
    # Hapus path jika ada
    HOST="${HOST%%/*}"
}

function validate_domain() {
    local domain_to_check="$1"
    # Hapus scheme untuk validasi
    domain_to_check="${domain_to_check#*//}"
    local host_part="${domain_to_check%%:*}"

    # Regex untuk domain dan IP
    local ip_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'
    local domain_regex='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$'

    if [[ "$host_part" =~ $ip_regex || "$host_part" =~ $domain_regex ]]; then
        return 0 # Success
    else
        return 1 # Failure
    fi
}

function interactive_mode() {
    clear
    echo -e "${YELLOW}This tool will perform security tests on the target domain.${END}"
    echo -e "${DIM}Press Ctrl+C at any time to stop the scan.${END}\n"

    while true; do
        # Menggunakan 'echo -n' untuk menampilkan prompt tanpa baris baru
        echo -n "Target Domain: "
        
        # Membaca input pengguna ke dalam variabel 'domain'
        read domain
        
        domain=$(echo "$domain" | xargs) # Menghapus spasi di awal/akhir

        # Logika validasi dan konfirmasi tetap sama
        if validate_domain "$domain"; then
            echo -e "${GREEN}Valid target: ${domain}${END}"
            echo -e "\n${RED}Press Enter to Start...${END}"
            read -p "$(echo -e "${YELLOW}Ready to scan ${domain}?${END}\n${GREEN}Press Enter to continue or 'q' to quit: ${END}")" confirm
            if [[ "$confirm" == "q" ]]; then
                echo -e "${YELLOW}Exiting...${END}"
                exit 0
            fi
            TARGET="$domain"
            return
        else
            echo -e "${RED}✗ Error: Invalid domain or IP address format.${END}\n"
        fi
    done
}

function check_requirements() {
    echo -e "\n${CYAN}Checking system requirements...${END}"
    local missing_tools=()
    local all_ok=true
    
    for tool in nmap sslscan openssl curl timeout; do
        if ! command -v "$tool" &> /dev/null; then
            echo -e "  ${RED}✗${END} ${tool}"
            missing_tools+=("$tool")
            all_ok=false
        else
            echo -e "  ${GREEN}✓${END} ${tool}"
        fi
    done

    if ! $all_ok; then
        echo -e "\n${RED}Error: Missing required tools: ${missing_tools[*]}${END}"
        echo -e "${YELLOW}Please install them to continue. For Debian/Ubuntu:"
        echo -e "${DIM}  sudo apt-get update && sudo apt-get install ${missing_tools[*]} coreutils${END}"
        exit 1
    fi
    echo -e "\n${GREEN}✓ All requirements satisfied!${END}"
}

# --- Fungsi Utama ---
function main() {
    # Parse argumen
    if [[ "$1" == "-o" && -n "$2" ]]; then
        OUTPUT_DIR="$2"
    fi

    check_requirements

    while true; do
        interactive_mode
        
        # Inisialisasi untuk pemindaian baru
        VULNERABILITIES=()
        RESULTS=()
        TOTAL_CHECKS=0
        VULNERABLE_COUNT=0
        SECURE_COUNT=0
        
        parse_target "$TARGET"

        # Buat file log unik untuk pemindaian ini
        mkdir -p "$OUTPUT_DIR"
        local timestamp=$(date '+%Y%m%d_%H%M%S')
        LOG_FILE="${OUTPUT_DIR}/command_log_${timestamp}.log"
        touch "$LOG_FILE"

        print_banner
        
        test_ssl_tls
        sleep 0.5
        test_http_security
        sleep 0.5
        test_weak_crypto
        
        print_summary

        read -p "$(echo -e "\n${YELLOW}Would you like to scan another domain? (y/n)${END}\n${GREEN}➜ ${END}")" another
        if [[ "${another,,}" != "y" ]]; then
            echo -e "${YELLOW}Exiting scanner. Goodbye!${END}"
            break
        fi
    done
}

# Jalankan skrip
main "$@"