#!/bin/bash

# Colors
MAGENTA='\e[1;35m'
NC='\e[0m' # No Color
BLUE='\e[1;34m'
GREEN='\e[1;32m'
RED='\e[1;31m'
YELLOW='\e[1;33m'

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "Mass XSS Scanner"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced Cross-Site Scripting Scanner${NC}"
    echo -e "${MAGENTA}[*] Version: 1.0${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    echo -e "\n${BLUE}[+] Target Configuration${NC}"
    read -p $'\e[1;35m🌐 Enter the domain you want to explore: \e[0m' domain
    echo -e "${GREEN}[*] Target set to: $domain${NC}"
    sleep 1
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f $domain
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Domain enumeration
enumerate_domain() {
    echo -e "\n${BLUE}[+] Starting Domain Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p $domain/{sources,result/{xss,wayback,gf,httpx}}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d $domain -o $domain/sources/subfinder.txt
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat $domain/sources/*.txt > $domain/sources/all.txt
    
    echo -e "${GREEN}[✓] Domain enumeration completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    cat $domain/sources/all.txt | httprobe | tee $domain/result/httpx/httpx.txt
    echo -e "${GREEN}[✓] HTTP probing completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat $domain/result/httpx/httpx.txt | waybackurls | anew $domain/result/wayback/wayback-tmp.txt 
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat $domain/result/wayback/wayback-tmp.txt | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > $domain/result/wayback/wayback.txt
    
    rm $domain/result/wayback/wayback-tmp.txt
    echo -e "${GREEN}[✓] Wayback collection completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    cat "$domain/result/wayback/wayback.txt" | \
        ffuf -c -u "FUZZ" -w - -of csv -o "$domain/result/wayback/valid-tmp.txt" -t 100 -rate 1000
    
    cat $domain/result/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/result/wayback/valid.txt
    rm $domain/result/wayback/valid-tmp.txt
    echo -e "${GREEN}[✓] URL validation completed${NC}"
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
    
    for pattern in "${!patterns[@]}"; do
        echo -e "${MAGENTA}[*] Checking for ${patterns[$pattern]}...${NC}"
        gf $pattern $domain/result/wayback/valid.txt | tee $domain/result/gf/${pattern}.txt
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# XSS testing
test_xss() {
    echo -e "\n${BLUE}[+] Testing for XSS vulnerabilities...${NC}"
    
    echo -e "${MAGENTA}[*] Processing potential XSS endpoints...${NC}"
    cat $domain/result/gf/xss.txt | \
        grep -E '\bhttps?://\S+?=\S+' | \
        grep -E '\.php|\.asp' | \
        sort -u | \
        sed 's/\(=[^&]*\)/=/g' | \
        tee $domain/sources/urls-xss.txt | \
        sort -u -o $domain/sources/urls-xss.txt
    
    echo -e "${MAGENTA}[*] Running KXSS scanner...${NC}"
    cat $domain/sources/urls-xss.txt | kxss > $domain/result/xss/kxss-results.txt
    
    echo -e "${GREEN}[✓] XSS testing completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Send initial message
        message="🔍 Mass XSS scan completed for domain: $domain\n📤 Sending results..."
        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files
        find "$domain" -type f | while read file; do
            echo -e "${MAGENTA}[*] Sending: $(basename $file)${NC}"
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