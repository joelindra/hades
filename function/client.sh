#!/bin/bash

# Inisialisasi warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
LIGHTBLACK_EX='\033[0;90m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Fungsi untuk mencetak banner
print_banner() {
    echo -e "${LIGHTBLACK_EX}──────────────────────────────────────────────────\n${NC}"
}

# Fungsi untuk memeriksa dependensi yang diperlukan
check_dependencies() {
    local missing=()
    # Periksa perintah yang wajib ada
    for cmd in curl jq; do
        if ! command -v "$cmd" &> /dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${RED}Error: Perintah berikut tidak ditemukan: ${missing[*]}.${NC}"
        echo -e "${YELLOW}Silakan install terlebih dahulu untuk melanjutkan.${NC}"
        echo -e "${YELLOW}Contoh install di Debian/Ubuntu: sudo apt update && sudo apt install curl jq${NC}"
        exit 1
    fi
}

# Fungsi untuk memvalidasi dan menormalkan URL
validate_url() {
    local url=$1
    # Tambahkan https:// jika tidak ada protokol
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi
    # Pemeriksaan untuk memastikan URL dapat dijangkau dengan timeout
    if curl --output /dev/null --silent --head --fail --max-time 10 --connect-timeout 5 "$url" 2>/dev/null; then
        echo "$url"
    else
        echo ""
    fi
}

# 1. Uji Clickjacking - 
test_clickjacking() {
    local url=$1
    echo -e "\n${YELLOW}Clickjacking ${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa apakah situs web dapat disematkan dalam iframe...\n${NC}"
    
    # Gunakan timeout dan error handling yang lebih baik
    headers=$(curl -sI --max-time 10 "$url" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo -e "${RED}   ✗ ERROR: Tidak dapat mengambil header dari $url${NC}"
        return 1
    fi
    
    xfo_header=$(echo "$headers" | grep -i '^x-frame-options:' | head -1)
    csp_header=$(echo "$headers" | grep -i '^content-security-policy:' | head -1)
    
    vulnerable=true
    protections=()
    
    if [[ -n "$xfo_header" ]]; then
        header_value=$(echo "$xfo_header" | awk -F': ' '{print $2}' | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
        if [[ "$header_value" =~ ^(deny|sameorigin)$ ]]; then
            vulnerable=false
            protections+=("X-Frame-Options: $(echo "$xfo_header" | awk -F': ' '{print $2}' | tr -d '[:space:]')")
        fi
    fi
    
    if [[ -n "$csp_header" ]]; then
        if echo "$csp_header" | grep -qi "frame-ancestors"; then
            vulnerable=false
            protections+=("CSP frame-ancestors")
        fi
    fi
    
    if $vulnerable; then
        echo -e "${RED}   ✗ VULNERABLE"
        echo -e "${LIGHTBLACK_EX}   → Situs web dapat disematkan dalam iframe berbahaya."
        echo -e "${LIGHTBLACK_EX}   → Risiko: Serangan UI Redressing, pengungkapan informasi sensitif."
        echo -e "\n${WHITE}   Perbaikan: Tambahkan header 'X-Frame-Options: DENY' atau 'X-Frame-Options: SAMEORIGIN'."
    else
        echo -e "${GREEN}   ✓ TERLINDUNGI"
        for p in "${protections[@]}"; do
            echo -e "${LIGHTBLACK_EX}   → Ditemukan perlindungi: $p"
        done
    fi
}

# 2. Uji CORS - 
test_cors() {
    local url=$1
    echo -e "\n${YELLOW}CORS${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa kebijakan cross-origin resource sharing...\n${NC}"

    origins=('https://evil.com' 'null' 'https://attacker.com')
    vulnerable=false
    vuln_details=()

    for origin in "${origins[@]}"; do
        headers=$(curl -sI -H "Origin: $origin" --max-time 10 "$url" 2>/dev/null)
        if [ $? -eq 0 ]; then
            acao=$(echo "$headers" | grep -i '^access-control-allow-origin:' | awk -F': ' '{print $2}' | tr -d '\r\n' | xargs)
            acac=$(echo "$headers" | grep -i '^access-control-allow-credentials:' | awk -F': ' '{print $2}' | tr -d '\r\n' | xargs)

            if [[ "$acao" == "$origin" ]] || [[ "$acao" == "*" ]]; then
                vulnerable=true
                vuln_details+=("Origin: $origin → ACAO: $acao")
                if [[ "$acac" == "true" ]]; then
                    vuln_details+=("  ⚠ Dengan Access-Control-Allow-Credentials: true!")
                fi
            fi
        fi
    done

    if $vulnerable; then
        echo -e "${RED}   ✗ VULNERABLE"
        for detail in "${vuln_details[@]}"; do
            echo -e "${LIGHTBLACK_EX}   → $detail"
        done
        echo -e "${LIGHTBLACK_EX}   → Risiko: Akses tidak sah ke sumber daya, eksfiltrasi data."
        echo -e "\n${WHITE}   Perbaikan: Terapkan daftar putih origin yang ketat untuk ACAO."
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ditemukan konfigurasi CORS yang berbahaya."
    fi
}

# 3. Uji WebSockets -   
test_websockets() {
    local url=$1
    echo -e "\n${YELLOW}WebSockets${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa keSECUREan implementasi WebSocket...\n${NC}"
    
    domain=$(echo "$url" | awk -F/ '{print $3}')
    
    # Periksa apakah ada endpoint WebSocket dengan mencari pola umum
    ws_patterns=$(curl -s --max-time 10 "$url" 2>/dev/null | grep -oE '(ws://|wss://)[^"'\''[:space:]]+' | head -5)
    
    if [[ -n "$ws_patterns" ]]; then
        echo -e "${YELLOW}   ⓘ Endpoint WebSocket terdeteksi:"
        echo "$ws_patterns" | while read -r ws_url; do
            echo -e "${LIGHTBLACK_EX}   → $ws_url"
        done
        
        # Periksa apakah ada validasi Origin
        if curl -s --max-time 5 "$url" 2>/dev/null | grep -qi "origin.*check\|validate.*origin"; then
            echo -e "${GREEN}   ✓ KEMUNGKINAN SECURE"
            echo -e "${LIGHTBLACK_EX}   → Ditemukan indikasi validasi Origin."
        else
            echo -e "${YELLOW}   ⚠ PERLU DIPERIKSA MANUAL"
            echo -e "${LIGHTBLACK_EX}   → Tidak dapat memverifikasi validasi Origin secara otomatis."
        fi
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada endpoint WebSocket yang terdeteksi."
    fi
}

# 4. Uji Injeksi CSS - 
test_css_injection() {
    local url=$1
    echo -e "\n${YELLOW}CSS Injection${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa keVULNERABLE injeksi CSS...\n${NC}"

    payloads=(
        "';--}}body{background:red!important}"
        "\"}*{background:red!important}/*"
        "</style><style>body{background:red}"
    )
    
    vulnerable=false
    
    for payload in "${payloads[@]}"; do
        encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        
        # Test beberapa parameter umum
        for param in "q" "search" "query" "input" "css"; do
            response=$(curl -s -L --max-time 10 "${url}?${param}=${encoded_payload}" 2>/dev/null)
            if echo "$response" | grep -q "background:red"; then
                echo -e "${RED}   ✗ VULNERABLE"
                echo -e "${LIGHTBLACK_EX}   → Injeksi CSS berhasil melalui parameter '$param'."
                echo -e "${LIGHTBLACK_EX}   → Payload: $payload"
                vulnerable=true
                break 2
            fi
        done
    done
    
    if ! $vulnerable; then
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada injeksi CSS yang berhasil."
    else
        echo -e "${LIGHTBLACK_EX}   → Risiko: Eksfiltrasi data, defacement, clickjacking."
        echo -e "\n${WHITE}   Perbaikan: Validasi dan sanitasi input, implementasi CSP."
    fi
}

# 5. Uji Pengalihan Klien - 
test_client_redirect() {
    local url=$1
    echo -e "\n${YELLOW}Client Redirect${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa keVULNERABLE open redirect...\n${NC}"
    
    payloads=(
        "https://evil.com"
        "//evil.com"
        "http://evil.com"
        "javascript:alert(1)"
    )
    
    vulnerable=false
    
    for payload in "${payloads[@]}"; do
        encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        
        for param in "redirect" "url" "return" "next" "goto" "target"; do
            # Gunakan -I untuk header saja dan cek Location
            headers=$(curl -sI -L --max-redirects 1 --max-time 10 "${url}?${param}=${encoded_payload}" 2>/dev/null)
            
            if echo "$headers" | grep -qi "location:.*evil.com"; then
                echo -e "${RED}   ✗ VULNERABLE"
                echo -e "${LIGHTBLACK_EX}   → Open redirect melalui parameter '$param'."
                echo -e "${LIGHTBLACK_EX}   → Payload: $payload"
                vulnerable=true
                break 2
            fi
        done
    done
    
    if ! $vulnerable; then
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada open redirect yang ditemukan."
    else
        echo -e "${LIGHTBLACK_EX}   → Risiko: Phishing, distribusi malware."
        echo -e "\n${WHITE}   Perbaikan: Validasi URL dengan whitelist domain."
    fi
}

# 6. Uji Cross-Site Flashing - 
test_cross_site_flashing() {
    local url=$1
    echo -e "\n${YELLOW}Cross-Site Flashing${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa keberadaan konten Flash (file SWF)...\n${NC}"
    
    response=$(curl -s -L --max-time 10 "$url" 2>/dev/null)
    swf_files=$(echo "$response" | grep -oE '[^"'\''[:space:]]+\.swf[^"'\''[:space:]]*' | head -10)
    
    if [[ -n "$swf_files" ]]; then
        echo -e "${RED}   ✗ POTENTIAL VULNERABLE"
        echo -e "${LIGHTBLACK_EX}   → File SWF terdeteksi:"
        echo "$swf_files" | while read -r swf; do
            echo -e "${LIGHTBLACK_EX}     • $swf"
        done
        echo -e "${LIGHTBLACK_EX}   → Risiko: XSS melalui Flash, clickjacking."
        echo -e "\n${WHITE}   Perbaikan: Hapus Flash atau gunakan versi terbaru dengan security sandbox."
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada konten Flash yang terdeteksi."
    fi
}

# 7. Uji Penyimpanan Browser - 
test_browser_storage() {
    local url=$1
    echo -e "\n${YELLOW}Browser Storage${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa atribut cookie yang SECURE...\n${NC}"
    
    headers=$(curl -sI -L --max-time 10 "$url" 2>/dev/null)
    cookies=$(echo "$headers" | grep -i '^set-cookie:')
    
    if [[ -n "$cookies" ]]; then
        insecure_cookies=()
        
        while IFS= read -r cookie_line; do
            cookie_name=$(echo "$cookie_line" | awk -F'[=;]' '{print $1}' | awk -F': ' '{print $2}')
            
            missing_attrs=()
            if ! echo "$cookie_line" | grep -qi "httponly"; then
                missing_attrs+=("HttpOnly")
            fi
            if ! echo "$cookie_line" | grep -qi "secure"; then
                missing_attrs+=("Secure")
            fi
            if ! echo "$cookie_line" | grep -qi "samesite"; then
                missing_attrs+=("SameSite")
            fi
            
            if [ ${#missing_attrs[@]} -gt 0 ]; then
                insecure_cookies+=("$cookie_name: missing ${missing_attrs[*]}")
            fi
        done <<< "$cookies"
        
        if [ ${#insecure_cookies[@]} -gt 0 ]; then
            echo -e "${RED}   ✗ POTENTIAL VULNERABLE"
            for cookie_issue in "${insecure_cookies[@]}"; do
                echo -e "${LIGHTBLACK_EX}   → $cookie_issue"
            done
            echo -e "${LIGHTBLACK_EX}   → Risiko: Session hijacking, XSS, CSRF."
            echo -e "\n${WHITE}   Perbaikan: Tambahkan Secure, HttpOnly, SameSite pada semua cookie."
        else
            echo -e "${GREEN}   ✓ SECURE"
            echo -e "${LIGHTBLACK_EX}   → Semua cookie memiliki atribut keSECUREan yang diperlukan."
        fi
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada cookie yang ditemukan."
    fi
}

# Fungsi pembantu untuk menggabungkan URL - 
urljoin() {
    local base_url=$1
    local path=$2
    
    # Jika path adalah URL absolut, kembalikan path itu sendiri
    if [[ "$path" =~ ^https?:// ]]; then
        echo "$path"
    # Jika path dimulai dengan //, gabungkan dengan scheme dari base_url
    elif [[ "$path" == //* ]]; then
        local scheme=$(echo "$base_url" | awk -F: '{print $1}')
        echo "$scheme:$path"
    # Jika path dimulai dengan /, gabungkan dengan root dari base_url
    elif [[ "$path" == /* ]]; then
        local base_root=$(echo "$base_url" | awk -F/ '{print $1"//"$3}')
        echo "$base_root$path"
    # Jika path adalah relatif
    else
        local base_dir=$(dirname "$base_url")
        if [[ "$base_dir" == "." ]]; then
            base_dir="$base_url"
        fi
        echo "$base_dir/$path"
    fi
}

# 8. Uji CSSI - 
test_cssi() {
    local url=$1
    echo -e "\n${YELLOW}Cross-Site Script Inclusion${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa paparan data sensitif dalam file JavaScript...\n${NC}"
    
    response=$(curl -s -L --max-time 10 "$url" 2>/dev/null)
    js_files=$(echo "$response" | grep -oE 'src="[^"]+\.js[^"]*"' | sed 's/src="//g; s/"//g' | head -10)
    
    found=false
    sensitive_patterns=('api_key' 'apikey' 'token' 'secret' 'password' 'private_key' 'access_token')
    
    if [[ -n "$js_files" ]]; then
        while IFS= read -r js; do
            [[ -z "$js" ]] && continue
            js_url=$(urljoin "$url" "$js")
            js_content=$(curl -s -L --max-time 5 "$js_url" 2>/dev/null)
            
            for pattern in "${sensitive_patterns[@]}"; do
                if echo "$js_content" | grep -qi "$pattern"; then
                    echo -e "${RED}   ✗ POTENTIAL VULNERABLE"
                    echo -e "${LIGHTBLACK_EX}   → Data sensitif ditemukan di: $js_url"
                    echo -e "${LIGHTBLACK_EX}   → Pattern: $pattern"
                    found=true
                    break
                fi
            done
            [[ $found == true ]] && break
        done <<< "$js_files"
    fi
    
    if $found; then
        echo -e "${LIGHTBLACK_EX}   → Risiko: Pengungkapan kredensial, API abuse."
        echo -e "\n${WHITE}   Perbaikan: Jangan simpan data sensitif di JavaScript client-side."
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada data sensitif terdeteksi dalam JavaScript."
    fi
}

# 9. Uji Tabnabbing - 
test_tabnabbing() {
    local url=$1
    echo -e "\n${YELLOW}Tabnabbing${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa tautan dengan target='_blank' tanpa rel='noopener'...\n${NC}"
    
    response=$(curl -s -L --max-time 10 "$url" 2>/dev/null)
    
    # Cari link dengan target="_blank" 
    blank_links=$(echo "$response" | grep -o '<a[^>]*target=["'"'"']_blank["'"'"'][^>]*>' | head -10)
    
    if [[ -n "$blank_links" ]]; then
        vulnerable_links=0
        total_links=0
        
        while IFS= read -r link; do
            [[ -z "$link" ]] && continue
            ((total_links++))
            
            if ! echo "$link" | grep -qi 'rel=["'"'"'][^"'"'"']*noopener'; then
                ((vulnerable_links++))
            fi
        done <<< "$blank_links"
        
        if [ $vulnerable_links -gt 0 ]; then
            echo -e "${RED}   ✗ VULNERABLE"
            echo -e "${LIGHTBLACK_EX}   → $vulnerable_links dari $total_links link target='_blank' tanpa rel='noopener'."
            echo -e "${LIGHTBLACK_EX}   → Risiko: Reverse tabnabbing, phishing."
            echo -e "\n${WHITE}   Perbaikan: Tambahkan rel='noopener noreferrer' pada semua target='_blank'."
        else
            echo -e "${GREEN}   ✓ SECURE"
            echo -e "${LIGHTBLACK_EX}   → Semua link target='_blank' memiliki rel='noopener'."
        fi
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada link dengan target='_blank' ditemukan."
    fi
}

# 10. Uji Eksekusi JavaScript - 
test_js_execution() {
    local url=$1
    echo -e "\n${YELLOW}JavaScript Execution${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa pola DOM XSS yang berbahaya...\n${NC}"
    
    response=$(curl -s -L --max-time 10 "$url" 2>/dev/null)
    
    # Pola-pola berbahaya untuk DOM XSS
    dangerous_patterns=(
        'innerHTML\s*='
        'outerHTML\s*='
        'document\.write\s*\('
        'document\.writeln\s*\('
        'eval\s*\('
        'setTimeout\s*\([^,]*[^)]'
        'setInterval\s*\([^,]*[^)]'
        'Function\s*\('
        'location\.href\s*='
        'location\.replace\s*\('
    )
    
    found_patterns=()
    
    for pattern in "${dangerous_patterns[@]}"; do
        if echo "$response" | grep -qE "$pattern"; then
            found_patterns+=("$pattern")
        fi
    done
    
    if [ ${#found_patterns[@]} -gt 0 ]; then
        echo -e "${RED}   ✗ POTENTIAL VULNERABLE"
        echo -e "${LIGHTBLACK_EX}   → Ditemukan pola berbahaya:"
        for pattern in "${found_patterns[@]}"; do
            echo -e "${LIGHTBLACK_EX}     • $pattern"
        done
        echo -e "${LIGHTBLACK_EX}   → Risiko: DOM-based XSS, code injection."
        echo -e "\n${WHITE}   Perbaikan: Gunakan textContent/innerText, validasi input, CSP."
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada pola DOM XSS berbahaya yang terdeteksi."
    fi
}

# 11. Uji Manipulasi Sumber Daya - 
test_client_side_resource_manipulation() {
    local url=$1
    echo -e "\n${YELLOW}Client-Side Resource${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa manipulasi resource melalui parameter URL...\n${NC}"
    
    payloads=(
        "https://evil.com/malicious.js"
        "javascript:alert(1)"
        "data:text/javascript,alert(1)"
    )
    
    vulnerable=false
    
    for payload in "${payloads[@]}"; do
        encoded_payload=$(printf '%s' "$payload" | jq -sRr @uri 2>/dev/null || echo "$payload")
        
        for param in "src" "script" "js" "css" "stylesheet" "resource"; do
            response=$(curl -s -L --max-time 10 "${url}?${param}=${encoded_payload}" 2>/dev/null)
            
            if echo "$response" | grep -q "src=\"$payload\"" || echo "$response" | grep -q "href=\"$payload\""; then
                echo -e "${RED}   ✗ VULNERABLE"
                echo -e "${LIGHTBLACK_EX}   → Resource manipulation melalui parameter '$param'."
                echo -e "${LIGHTBLACK_EX}   → Payload: $payload"
                vulnerable=true
                break 2
            fi
        done
    done
    
    if ! $vulnerable; then
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada manipulasi resource yang berhasil."
    else
        echo -e "${LIGHTBLACK_EX}   → Risiko: XSS, malicious script injection."
        echo -e "\n${WHITE}   Perbaikan: Validasi ketat URL resource, gunakan whitelist."
    fi
}

# 12. Uji Pesan Web - 
test_web_messaging() {
    local url=$1
    echo -e "\n${YELLOW}Web Messaging${WHITE} $url"
    echo -e "${LIGHTBLACK_EX}Memeriksa implementasi postMessage yang tidak SECURE...\n${NC}"
    
    response=$(curl -s -L --max-time 10 "$url" 2>/dev/null)
    
    # Cari penggunaan postMessage
    postmessage_usage=$(echo "$response" | grep -o 'postMessage([^)]*)')
    
    if [[ -n "$postmessage_usage" ]]; then
        # Periksa penggunaan wildcard origin
        if echo "$response" | grep -q 'postMessage.*\*'; then
            echo -e "${RED}   ✗ VULNERABLE"
            echo -e "${LIGHTBLACK_EX}   → postMessage menggunakan wildcard origin ('*')."
            echo -e "${LIGHTBLACK_EX}   → Risiko: Data leakage, XSS, unauthorized actions."
            echo -e "\n${WHITE}   Perbaikan: Tentukan target origin spesifik, validasi event.origin."
        else
            # Periksa event listener untuk message
            if echo "$response" | grep -q 'addEventListener.*message'; then
                if echo "$response" | grep -q 'event\.origin'; then
                    echo -e "${GREEN}   ✓ KEMUNGKINAN SECURE"
                    echo -e "${LIGHTBLACK_EX}   → postMessage dengan validasi origin terdeteksi."
                else
                    echo -e "${YELLOW}   ⚠ PERLU REVIEW"
                    echo -e "${LIGHTBLACK_EX}   → postMessage listener tanpa validasi origin eksplisit."
                fi
            else
                echo -e "${YELLOW}   ⓘ postMessage terdeteksi, perlu analisis manual."
            fi
        fi
    else
        echo -e "${GREEN}   ✓ SECURE"
        echo -e "${LIGHTBLACK_EX}   → Tidak ada penggunaan postMessage yang terdeteksi."
    fi
}

# Menampilkan menu
show_menu() {
    echo -e "${CYAN}Available Security Tests:${NC}"
    echo "   1. Clickjacking            - Check iframe embedding protection"
    echo "   2. CORS                    - Check cross-origin policies"
    echo "   3. WebSockets              - Check WebSocket security"
    echo "   4. CSS Injection           - Check CSS injection vulnerabilities"
    echo "   5. Client Redirect         - Check open redirect vulnerabilities"
    echo "   6. Cross-Site Flashing     - Check for insecure Flash content"
    echo "   7. Browser Storage         - Check client-side storage security"
    echo "   8. CSSI                    - Check Cross-Site Script Inclusion"
    echo "   9. Tabnabbing              - Check for reverse tabnabbing"
    echo "  10. JavaScript Execution    - Check for DOM XSS patterns"
    echo "  11. Client-Side Resource    - Check resource manipulation"
    echo "  12. Web Messaging           - Check postMessage security"
    echo "  13. All                     - Run all security tests"
}

# Fungsi utama
main() {
    check_dependencies
    print_banner
    
    local target=""
    
    while true; do
        clear
        echo -e "${YELLOW}Web Security Scanner${NC}"
        echo -e "${LIGHTBLACK_EX}This tool performs client-side security tests on web applications.${NC}\n"
        echo -n "Enter target: "
        read -r domain
        
        domain=$(echo "$domain" | xargs)
        
        if [[ -z "$domain" ]]; then
            continue
        fi
        
        target=$(validate_url "$domain")
        
        if [[ -n "$target" ]]; then
            clear
            echo -e "${GREEN}✓ Target validated: ${target}${NC}"
            break
        else
            echo -e "${RED}✗ Error: Invalid URL or unreachable. Please try again.${NC}"
            echo -n "Press Enter to continue..."
            read -r
        fi
    done

    print_banner
    show_menu
    
    local choice
    while true; do
        echo ""
        echo -n "Choose test (1-13): "
        read -r choice

        if [[ "$choice" =~ ^(1|2|3|4|5|6|7|8|9|10|11|12|13)$ ]]; then
            break
        fi
        echo -e "${RED}Invalid choice. Please enter a number between 1 and 13.${NC}"
    done
    
    echo -e "\n${LIGHTBLACK_EX}Starting security tests for $target...${NC}"
    echo -e "${LIGHTBLACK_EX}──────────────────────────────────────────────────${NC}"
    
    case $choice in
        1) test_clickjacking "$target" ;;
        2) test_cors "$target" ;;
        3) test_websockets "$target" ;;
        4) test_css_injection "$target" ;;
        5) test_client_redirect "$target" ;;
        6) test_cross_site_flashing "$target" ;;
        7) test_browser_storage "$target" ;;
        8) test_cssi "$target" ;;
        9) test_tabnabbing "$target" ;;
        10) test_js_execution "$target" ;;
        11) test_client_side_resource_manipulation "$target" ;;
        12) test_web_messaging "$target" ;;
        13)
            test_clickjacking "$target"
            test_cors "$target"
            test_websockets "$target"
            test_css_injection "$target"
            test_client_redirect "$target"
            test_cross_site_flashing "$target"
            test_browser_storage "$target"
            test_cssi "$target"
            test_tabnabbing "$target"
            test_js_execution "$target"
            test_client_side_resource_manipulation "$target"
            test_web_messaging "$target"
            ;;
    esac
    
    echo -e "\n${LIGHTBLACK_EX}──────────────────────────────────────────────────${NC}"
    echo -e "${GREEN}Security testing completed successfully!${NC}"
    echo -e "${YELLOW}Note: This tool provides basic security checks. Manual testing is recommended for comprehensive security assessment.${NC}\n"
}

# Error handling untuk interrupt
trap 'echo -e "\n${YELLOW}Scan interrupted by user.${NC}"; exit 0' INT

# Jalankan fungsi utama
main "$@"