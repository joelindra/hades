#!/bin/bash

# Colors
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

# Banner function
display_banner() {
    clear
}

# Input target function
input_target() {
    clear
    echo -e "${BLUE}👽 Mass Server Domain CSRF${NC}"
    echo ""
    
    while true; do
        echo -e "${YELLOW}[?] Masukkan domain target ${NC}(contoh: example.com)"
        echo -e "${YELLOW}[?] Ketik 'quit' untuk keluar${NC}"
        echo -ne "\n${GREEN}[+] Target domain: ${NC}"
        read -r input
        
        # Validasi input
        if [[ -z "$input" ]]; then
            echo -e "\n${RED}[!] Error: workspace tidak boleh kosong!${NC}"
            sleep 1
            continue
        elif [[ "$input" == "quit" ]]; then
            echo -e "\n${YELLOW}[!] Keluar dari program...${NC}"
            exit 0
        elif ! [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "\n${RED}[!] Error: Format workspace tidak valid!${NC}"
            sleep 1
            continue
        fi
        
        # Jika validasi berhasil
        echo -e "\n${GREEN}[✓] workspace target valid: $input${NC}"
        echo -e "${BLUE}[*] Memulai pemindaian...${NC}\n"
        sleep 1
        workspace="$input"  # Set workspace variable
        break
    done
    return 0
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f "$workspace"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# workspace enumeration
enumerate_workspace() {
    echo -e "\n${BLUE}[+] Starting workspace Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p "$workspace"/{sources,result/{nuclei,httpx,sqli,wayback,gf}}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$workspace" -o "$workspace/sources/subfinder.txt"
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$workspace" | tee "$workspace/sources/assetfinder.txt"
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat "$workspace/sources/"*.txt > "$workspace/sources/all.txt"
    
    total_workspaces=$(wc -l < "$workspace/sources/all.txt")
    echo -e "${GREEN}[✓] Found ${total_workspaces} subworkspaces${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    
    # Probe hosts dan simpan hasil sementara
    temp_file=$(mktemp)
    cat "$workspace/sources/all.txt" | httprobe | tee "$temp_file"
    
    # Deduplikasi: prioritaskan HTTPS daripada HTTP
    echo -e "${YELLOW}[+] Removing duplicates (prioritizing HTTPS)...${NC}"
    
    # Ekstrak workspace unik dan tentukan protokol terbaik
    awk -F'://' '{
        workspace = $2
        protocol = $1
        
        # Jika workspace belum ada atau protokol saat ini adalah https
        if (!(workspace in workspaces) || protocol == "https") {
            workspaces[workspace] = protocol "://" workspace
        }
    }
    END {
        for (d in workspaces) {
            print workspaces[d]
        }
    }' "$temp_file" | sort > "$workspace/result/httpx/httpx.txt"
    
    # Hapus file temporary
    rm -f "$temp_file"
    
    total_live=$(wc -l < "$workspace/result/httpx/httpx.txt")
    echo -e "${GREEN}[✓] Found ${total_live} live hosts (after deduplication)${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat "$workspace/result/httpx/httpx.txt" | waybackurls | anew "$workspace/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$workspace/result/wayback/wayback-tmp.txt" | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$workspace/result/wayback/wayback.txt"
    
    rm "$workspace/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$workspace/result/wayback/wayback.txt")
    echo -e "${GREEN}[✓] Found ${total_urls} unique URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    cat "$workspace/result/wayback/wayback.txt" | \
        ffuf -c -u "FUZZ" -w - -of csv -o "$workspace/result/wayback/valid-tmp.txt" -t 100 -rate 1000
    
    cat "$workspace/result/wayback/valid-tmp.txt" | grep http | awk -F "," '{print $1}' >> "$workspace/result/wayback/valid.txt"
    rm "$workspace/result/wayback/valid-tmp.txt"
    
    total_valid=$(wc -l < "$workspace/result/wayback/valid.txt")
    echo -e "${GREEN}[✓] Found ${total_valid} valid URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running pattern matching...${NC}"
    
    declare -A patterns=(
        ["sqli"]="SQL Injection"
        ["xss"]="Cross-Site Scripting"
        ["ssrf"]="Server-Side Request Forgery"
        ["rce"]="Remote Code Execution"
        ["idor"]="Insecure Direct Object Reference"
        ["lfi"]="Local File Inclusion"
        ["ssti"]="Server-Side Template Injection"
        ["debug_logic"]="Debug Logic"
        ["php-errors"]="PHP Errors"
    )
    
    total_patterns=${#patterns[@]}
    current=0
    
    for pattern in "${!patterns[@]}"; do
        ((current++))
        echo -e "${MAGENTA}[*] ($current/$total_patterns) Checking for ${patterns[$pattern]}...${NC}"
        gf "$pattern" "$workspace/result/wayback/valid.txt" | tee "$workspace/result/gf/${pattern}.txt"
        count=$(wc -l < "$workspace/result/gf/${pattern}.txt")
        echo -e "${GREEN}[✓] Found ${count} potential ${patterns[$pattern]} endpoints${NC}"
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

test_csrf() {
    echo -e "\n${BLUE}[+] Testing for CSRF Vulnerabilities...${NC}"
    
    # Create results directory
    mkdir -p "$workspace/result/csrf"
    
    # Create or check for URLs file
    if [[ ! -d "$workspace/result/gf" ]]; then
        mkdir -p "$workspace/result/gf"
    fi
    
    # First, find forms or endpoints that might be vulnerable to CSRF
    if [[ ! -f "$workspace/result/gf/urls.txt" ]]; then
        echo -e "${YELLOW}[!] URL list not found! Using all discovered URLs.${NC}"
        find "$workspace" -name "*.txt" -type f -exec grep -l "http" {} \; | xargs cat | sort -u > "$workspace/result/gf/urls.txt"
    fi
    
    # Create a file for potential form URLs to test
    grep -i -E "login|signup|register|password|reset|update|profile|settings|account|payment|checkout|contact|subscribe|admin|dashboard" "$workspace/result/gf/urls.txt" > "$workspace/result/csrf/potential_csrf_urls.txt"
    
    # If no potential URLs found, use a broader search
    if [[ ! -s "$workspace/result/csrf/potential_csrf_urls.txt" ]]; then
        echo -e "${YELLOW}[!] No specific form URLs found. Testing all discovered URLs.${NC}"
        cp "$workspace/result/gf/urls.txt" "$workspace/result/csrf/potential_csrf_urls.txt"
    fi
    
    total_urls=$(wc -l < "$workspace/result/csrf/potential_csrf_urls.txt")
    current=0
    vulnerable=0
    
    echo -e "${GREEN}[*] Testing $total_urls potential URLs for CSRF vulnerabilities${NC}"
    
    # Test each URL for CSRF vulnerabilities
    while IFS= read -r url; do
        ((current++))
        echo -e "\n${YELLOW}[*] Testing URL ($current/$total_urls): $url${NC}"
        
        # Get the initial page to find forms and check for CSRF protections
        response=$(curl -s -L -i -H "User-Agent: Mozilla/5.0" --max-time 15 "$url")
        
        # Extract any forms from the response
        forms=$(echo "$response" | grep -i -o '<form[^>]*>.*</form>' | sed 's/<script.*<\/script>//g')
        
        # Case 1: Check if the page has forms but without CSRF tokens
        if [[ -n "$forms" ]]; then
            echo -e "${BLUE}[+] Found form(s) on the page${NC}"
            
            # Check for common CSRF protection mechanisms
            has_csrf_token=$(echo "$forms" | grep -i -E 'csrf|token|nonce|authenticity')
            has_samesite=$(echo "$response" | grep -i "Set-Cookie:" | grep -i -E "SameSite=strict|SameSite=lax")
            has_referer_policy=$(echo "$response" | grep -i "Referrer-Policy:" | grep -i -E "same-origin|strict-origin")
            
            # If none of the CSRF protections are found in a form with state-changing methods
            if [[ -z "$has_csrf_token" ]] && [[ -z "$has_samesite" ]] && [[ -z "$has_referer_policy" ]] && echo "$forms" | grep -i -q -E 'method="post"|method=post|method="put"|method="delete"'; then
                echo -e "${RED}[!] Potential CSRF Vulnerability: Form without CSRF protection${NC}"
                echo -e "${RED}[!] Vulnerable URL: $url${NC}"
                # Save to results
                echo "$url [Missing CSRF Token in Form]" >> "$workspace/result/csrf/vulnerable.txt"
                ((vulnerable++))
                
                # Extract form action to find the endpoint
                form_action=$(echo "$forms" | grep -i -o 'action="[^"]*"' | cut -d'"' -f2)
                if [[ -n "$form_action" ]]; then
                    # Construct full URL if relative path
                    if [[ "$form_action" == /* ]]; then
                        base_url=$(echo "$url" | grep -o 'https\?://[^/]*')
                        form_action="${base_url}${form_action}"
                    elif [[ "$form_action" != http* ]]; then
                        form_action="${url%/*}/${form_action}"
                    fi
                    echo -e "${YELLOW}[*] Form submission endpoint: $form_action${NC}"
                    echo "$form_action [Form Submission Endpoint]" >> "$workspace/result/csrf/endpoints.txt"
                fi
            else
                # Log what protections were found
                if [[ -n "$has_csrf_token" ]]; then
                    echo -e "${GREEN}[✓] CSRF token detected${NC}"
                    echo "$url [Has CSRF Token]" >> "$workspace/result/csrf/protected.txt"
                fi
                if [[ -n "$has_samesite" ]]; then
                    echo -e "${GREEN}[✓] SameSite cookie attribute detected${NC}"
                    echo "$url [Has SameSite Cookie]" >> "$workspace/result/csrf/protected.txt"
                fi
                if [[ -n "$has_referer_policy" ]]; then
                    echo -e "${GREEN}[✓] Strict Referrer Policy detected${NC}"
                    echo "$url [Has Strict Referrer Policy]" >> "$workspace/result/csrf/protected.txt"
                fi
            fi
        fi
        
        # Case 2: Check state-changing endpoints without CSRF protection
        # Find any API or state-changing endpoints in the page
        endpoints=$(echo "$response" | grep -o 'href="[^"]*"' | cut -d'"' -f2 | grep -E 'api|json|/update|/delete|/add|/create|/edit')
        
        if [[ -n "$endpoints" ]]; then
            echo -e "${BLUE}[+] Found potential state-changing endpoints${NC}"
            
            # Loop through each endpoint and check for CSRF protection
            while read -r endpoint; do
                # Construct full URL if relative path
                if [[ "$endpoint" == /* ]]; then
                    base_url=$(echo "$url" | grep -o 'https\?://[^/]*')
                    full_endpoint="${base_url}${endpoint}"
                elif [[ "$endpoint" != http* ]]; then
                    full_endpoint="${url%/*}/${endpoint}"
                else
                    full_endpoint="$endpoint"
                fi
                
                echo -e "${BLUE}[+] Testing endpoint: $full_endpoint${NC}"
                
                # Test if the endpoint accepts POST/PUT requests without CSRF protections
                csrf_test_response=$(curl -s -i -X POST -H "Content-Type: application/x-www-form-urlencoded" -H "User-Agent: Mozilla/5.0" -d "test=1" --max-time 10 "$full_endpoint")
                
                # Check if the response indicates successful processing (no CSRF error)
                if ! echo "$csrf_test_response" | grep -i -q -E 'csrf|token|invalid|forbidden|unauthorized'; then
                    # Check HTTP status code (2xx or 3xx might indicate successful submission)
                    status_code=$(echo "$csrf_test_response" | grep -i "HTTP/" | grep -o -E '[0-9]{3}' | tail -1)
                    if [[ "$status_code" =~ ^(2|3)[0-9]{2}$ ]]; then
                        echo -e "${RED}[!] Potential CSRF Vulnerability: Endpoint accepts POST without CSRF validation${NC}"
                        echo -e "${RED}[!] Vulnerable endpoint: $full_endpoint${NC}"
                        echo -e "${RED}[!] Status code: $status_code${NC}"
                        echo "$full_endpoint [Status Code: $status_code]" >> "$workspace/result/csrf/api_vulnerable.txt"
                        ((vulnerable++))
                    fi
                else
                    echo -e "${GREEN}[✓] Endpoint has CSRF protection${NC}"
                    echo "$full_endpoint [Protected]" >> "$workspace/result/csrf/protected_endpoints.txt"
                fi
            done <<< "$endpoints"
        fi
        
        # Case 3: Test JSON endpoints specifically for lack of CSRF protection
        if echo "$url" | grep -i -q -E 'api|json'; then
            echo -e "${BLUE}[+] Testing API endpoint for CSRF protection${NC}"
            
            # Create a test JSON payload
            test_json='{
                "test": "csrf_probe",
                "action": "read"
            }'
            
            # Test with a standard web browser Origin and Referer
            random_string=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 8 | head -n 1)
            test_origin="https://attacker-${random_string}.com"
            
            json_test_response=$(curl -s -i -X POST -H "Content-Type: application/json" -H "Origin: $test_origin" -H "Referer: $test_origin/csrf.html" -H "User-Agent: Mozilla/5.0" -d "$test_json" --max-time 10 "$url")
            
            # Check if the endpoint accepted the request from a different origin
            status_code=$(echo "$json_test_response" | grep -i "HTTP/" | grep -o -E '[0-9]{3}' | tail -1)
            
            if [[ "$status_code" =~ ^(2|3)[0-9]{2}$ ]]; then
                # Check for CORS headers that might prevent CSRF
                acao=$(echo "$json_test_response" | grep -i "Access-Control-Allow-Origin:" | head -1)
                
                if [[ -z "$acao" ]] || [[ "$acao" == *"$test_origin"* ]] || [[ "$acao" == *"\*"* ]]; then
                    echo -e "${RED}[!] Potential CSRF Vulnerability: JSON API endpoint without protection${NC}"
                    echo -e "${RED}[!] Vulnerable endpoint: $url${NC}"
                    echo -e "${RED}[!] Status code: $status_code${NC}"
                    if [[ -n "$acao" ]]; then
                        echo -e "${RED}[!] CORS header: $acao${NC}"
                    fi
                    echo "$url [Status Code: $status_code, CORS: $acao]" >> "$workspace/result/csrf/json_vulnerable.txt"
                    ((vulnerable++))
                else
                    echo -e "${GREEN}[✓] API has CORS protection${NC}"
                    echo "$url [CORS Protected: $acao]" >> "$workspace/result/csrf/protected_api.txt"
                fi
            fi
        fi
        
    done < "$workspace/result/csrf/potential_csrf_urls.txt"
    
    # Group by workspaces and endpoint paths to identify patterns
    if [ -s "$workspace/result/csrf/vulnerable.txt" ] || [ -s "$workspace/result/csrf/api_vulnerable.txt" ] || [ -s "$workspace/result/csrf/json_vulnerable.txt" ]; then
        echo -e "\n${BLUE}[*] Analyzing vulnerability patterns by endpoint...${NC}"
        
        # Combine all vulnerable endpoints
        cat "$workspace/result/csrf/vulnerable.txt" "$workspace/result/csrf/api_vulnerable.txt" "$workspace/result/csrf/json_vulnerable.txt" 2>/dev/null | sort > "$workspace/result/csrf/all_vulnerable.txt"
        
        # Extract workspaces and paths for pattern analysis
        cat "$workspace/result/csrf/all_vulnerable.txt" | cut -d'/' -f3 | sort | uniq -c | sort -nr > "$workspace/result/csrf/vulnerable_workspaces.txt"
        cat "$workspace/result/csrf/all_vulnerable.txt" | grep -o '/[^/]*' | sort | uniq -c | sort -nr > "$workspace/result/csrf/vulnerable_paths.txt"
        
        # Show the most common vulnerable workspaces
        if [ -s "$workspace/result/csrf/vulnerable_workspaces.txt" ]; then
            echo -e "\n${YELLOW}[*] Most vulnerable workspaces:${NC}"
            head -5 "$workspace/result/csrf/vulnerable_workspaces.txt"
        fi
        
        # Show the most common vulnerable paths
        if [ -s "$workspace/result/csrf/vulnerable_paths.txt" ]; then
            echo -e "\n${YELLOW}[*] Most common vulnerable paths:${NC}"
            head -5 "$workspace/result/csrf/vulnerable_paths.txt"
        fi
    fi
    
    # Compile summary report
    echo -e "\n${BLUE}[*] CSRF Vulnerability Summary:${NC}"
    
    if [ -f "$workspace/result/csrf/vulnerable.txt" ] && [ -s "$workspace/result/csrf/vulnerable.txt" ]; then
        echo -e "\n${RED}[!] Forms Vulnerable to CSRF:${NC}"
        cat "$workspace/result/csrf/vulnerable.txt"
    fi
    
    if [ -f "$workspace/result/csrf/api_vulnerable.txt" ] && [ -s "$workspace/result/csrf/api_vulnerable.txt" ]; then
        echo -e "\n${RED}[!] API Endpoints Vulnerable to CSRF:${NC}"
        cat "$workspace/result/csrf/api_vulnerable.txt"
    fi
    
    if [ -f "$workspace/result/csrf/json_vulnerable.txt" ] && [ -s "$workspace/result/csrf/json_vulnerable.txt" ]; then
        echo -e "\n${RED}[!] JSON Endpoints Vulnerable to CSRF:${NC}"
        cat "$workspace/result/csrf/json_vulnerable.txt"
    fi
    
    if [ -f "$workspace/result/csrf/protected.txt" ] && [ -s "$workspace/result/csrf/protected.txt" ]; then
        echo -e "\n${GREEN}[✓] Protected Forms/Pages:${NC}"
        cat "$workspace/result/csrf/protected.txt"
    fi
    
    echo -e "\n${GREEN}[✓] Total potential CSRF vulnerabilities: $vulnerable${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Preparing to send results to Telegram...${NC}"
    if ! command -v curl &> /dev/null || ! command -v zip &> /dev/null; then
        echo -e "${RED}[!] 'curl' and 'zip' are required but not installed.${NC}"
        return 1
    fi

    if [[ ! -f "telegram_token.txt" || ! -f "telegram_chat_id.txt" ]]; then
        echo -e "${RED}[!] Telegram credentials (telegram_token.txt, telegram_chat_id.txt) not found.${NC}"
        return 1
    fi

    local token=$(<"telegram_token.txt")
    local chat_id=$(<"telegram_chat_id.txt")
    local result_dir="$workspace/result"

    local message
    message=$(printf "🔍 *CSRF Scan Completed for:* \`%s\`\n\n" "$workspace"
    printf "📊 *Summary:*\n"
    printf " • Total URLs: \`%s\`\n" "$(wc -l < "$result_dir/wayback/wayback.txt" 2>/dev/null || echo 0)"
    printf " • Valid URLs: \`%s\`\n" "$(wc -l < "$result_dir/wayback/valid.txt" 2>/dev/null || echo 0)"
    printf " • Potential CSRF: \`%s\`\n\n" "$(wc -l < "$workspace/result/csrf/vulnerable.txt" 2>/dev/null || echo 0)"
    printf "📤 Detailed results are attached in the zip file."
    )

    # Kirim pesan ringkasan
    echo -e "${BLUE}[*] Sending summary message...${NC}"
    curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
        -d chat_id="$chat_id" \
        -d text="$message" \
        -d parse_mode="Markdown" > /dev/null

    # 3. Arsipkan Hasil dan Kirim
    if [ -d "$result_dir" ] && [ "$(ls -A "$result_dir")" ]; then
        local archive_name="results-$(basename "$workspace")-$(date +%F).zip"
        
        echo -e "${BLUE}[*] Creating results archive: ${archive_name}${NC}"
        # Opsi -j (junk paths) agar file tidak dalam folder saat di-zip
        zip -r -j "$archive_name" "$result_dir" > /dev/null

        echo -e "${BLUE}[*] Uploading archive...${NC}"
        curl -s -X POST "https://api.telegram.org/bot$token/sendDocument" \
            -F chat_id="$chat_id" \
            -F document=@"$archive_name" \
            -F caption="All scan results for $workspace" > /dev/null
        
        rm "$archive_name" # Hapus file zip setelah dikirim
    else
        echo -e "${YELLOW}[!] No result files found to archive in '$result_dir'.${NC}"
    fi
    
    echo -e "${GREEN}[✓] Process completed. Results sent to Telegram.${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    check_waf
    enumerate_workspace
    probe_http
    collect_wayback
    validate_urls
    run_gf_patterns
    test_csrf
    send_to_telegram
    echo -e "\n${GREEN}[✓] Mass CSRF scan completed successfully!${NC}\n"
}

# Run the script
main