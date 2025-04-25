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
    figlet -w 100 -f small "Domain Reconnaissance"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced Domain Analysis Tool${NC}"
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

# Create directory structure
setup_folders() {
    echo -e "\n${BLUE}[+] Setting up workspace...${NC}"
    mkdir -p $domain/{sources,result/{wayback,gf}}
    echo -e "${GREEN}[✓] Workspace created${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f $domain
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    echo -e "${MAGENTA}[*] Fetching URLs...${NC}"
    echo "https://$domain/" | waybackurls | anew $domain/result/wayback/wayback-tmp.txt 
    
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
    ffuf -c -u "FUZZ" -w $domain/result/wayback/wayback.txt -of csv -o $domain/result/wayback/valid-tmp.txt
    
    cat $domain/result/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/result/wayback/valid.txt
    rm $domain/result/wayback/valid-tmp.txt
    echo -e "${GREEN}[✓] URL validation completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running GF pattern matching...${NC}"
    
    # Define patterns array
    patterns=(
        ["xss"]="Cross-Site Scripting"
        ["sqli"]="SQL Injection"
        ["ssrf"]="Server-Side Request Forgery"
        ["redirect"]="Open Redirects"
        ["rce"]="Remote Code Execution"
        ["idor"]="Insecure Direct Object Reference"
        ["lfi"]="Local File Inclusion"
        ["ssti"]="Server-Side Template Injection"
        ["debug_logic"]="Debug Logic"
        ["img-traversal"]="Image Traversal"
        ["interestingparams"]="Interesting Parameters"
        ["aws-keys"]="AWS Keys"
        ["base64"]="Base64 Strings"
        ["cors"]="CORS Misconfigurations"
        ["http-auth"]="HTTP Authentication"
        ["php-errors"]="PHP Errors"
        ["takeovers"]="Domain Takeovers"
        ["urls"]="URLs"
        ["s3-buckets"]="S3 Buckets"
        ["strings"]="Interesting Strings"
        ["upload-fields"]="Upload Fields"
        ["servers"]="Server Information"
        ["ip"]="IP Addresses"
    )
    
    for pattern in "${!patterns[@]}"; do
        echo -e "${MAGENTA}[*] Checking for ${patterns[$pattern]}...${NC}"
        gf $pattern $domain/result/wayback/valid.txt | tee $domain/result/gf/${pattern}.txt
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    # Load credentials
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Send initial message
        message="🔍 Reconnaissance completed for domain: $domain\n📤 Sending results..."
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
    setup_folders
    check_waf
    collect_wayback
    validate_urls
    run_gf_patterns
    send_to_telegram
    echo -e "\n${GREEN}[✓] Reconnaissance completed successfully!${NC}\n"
}

# Run the script
main