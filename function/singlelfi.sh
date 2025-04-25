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
    figlet -w 100 -f small "LFI Scanner"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced Local File Inclusion Scanner${NC}"
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

# Create directory structure and collect wayback data
setup_wayback() {
    echo -e "\n${BLUE}[+] Setting up workspace and collecting URLs...${NC}"
    
    # Create directory structure
    mkdir -p $domain/{sources,result/{gf,wayback,lfi}}
    
    echo -e "${MAGENTA}[*] Fetching URLs from Wayback Machine...${NC}"
    echo "https://$domain/" | waybackurls | anew $domain/result/wayback/wayback-tmp.txt 
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat $domain/result/wayback/wayback-tmp.txt | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | \
        sort -u > $domain/result/wayback/wayback.txt
    
    rm $domain/result/wayback/wayback-tmp.txt
    echo -e "${GREEN}[✓] URL collection completed${NC}"
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
    echo -e "\n${BLUE}[+] Running pattern matching for vulnerabilities...${NC}"
    
    # Define patterns with descriptions
    declare -A patterns=(
        ["lfi"]="Local File Inclusion"
        ["rce"]="Remote Code Execution"
        ["ssrf"]="Server-Side Request Forgery"
        ["sqli"]="SQL Injection"
        ["xss"]="Cross-Site Scripting"
        ["idor"]="Insecure Direct Object Reference"
        ["ssti"]="Server-Side Template Injection"
        ["debug_logic"]="Debug Logic"
        ["img-traversal"]="Image Traversal"
        ["php-errors"]="PHP Errors"
        ["takeovers"]="Domain Takeovers"
        ["aws-keys"]="AWS Keys"
        ["s3-buckets"]="S3 Buckets"
    )
    
    for pattern in "${!patterns[@]}"; do
        echo -e "${MAGENTA}[*] Checking for ${patterns[$pattern]}...${NC}"
        gf $pattern $domain/result/wayback/valid.txt | tee $domain/result/gf/${pattern}.txt
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# LFI testing
test_lfi() {
    echo -e "\n${BLUE}[+] Testing for LFI vulnerabilities...${NC}"
    echo -e "${MAGENTA}[*] This may take some time...${NC}"
    
    total_urls=$(wc -l < "$domain/result/gf/lfi.txt")
    current=0
    
    while IFS= read -r url; do
        ((current++))
        echo -e "${YELLOW}[*] Testing URL ($current/$total_urls): $url${NC}"
        
        if curl -s "$url" 2>/dev/null | grep -q "root:x"; then
            echo -e "${RED}[!] Vulnerable: $url${NC}" | tee -a "$domain/result/lfi/lfi.txt"
        else
            echo -e "${GREEN}[✓] Not vulnerable: $url${NC}" | tee -a "$domain/result/lfi/lfi.txt"
        fi
    done < "$domain/result/gf/lfi.txt"
    
    echo -e "${GREEN}[✓] LFI testing completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Send initial message
        message="🔍 LFI scan completed for domain: $domain\n📤 Sending results..."
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
    setup_wayback
    validate_urls
    run_gf_patterns
    test_lfi
    send_to_telegram
    echo -e "\n${GREEN}[✓] LFI scan completed successfully!${NC}\n"
}

# Run the script
main