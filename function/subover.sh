#!/bin/bash

# Colors
MAGENTA='\e[1;35m'
NC='\e[0m' # No Color
BLUE='\e[1;34m'
GREEN='\e[1;32m'
RED='\e[1;31m'

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "Subdomain Takeover Scanner"
    echo -e "${NC}"
    echo -e "${MAGENTA}[] Advanced Subdomain Analysis Tool${NC}"
    echo -e "${MAGENTA}[] Created by: Anonre${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target domain
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
    sleep 1
}

# Domain enumeration
enumerate_domains() {
    echo -e "\n${BLUE}[+] Starting Domain Enumeration...${NC}"

    # Create directory structure
    mkdir -p $domain/{sources,result/{takeover,httpx}}

    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d $domain -o $domain/sources/subfinder.txt

    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt

    cat $domain/sources/*.txt > $domain/sources/all.txt
    echo -e "${GREEN}[✓] Domain enumeration completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
check_http() {
    echo -e "\n${BLUE}[+] Probing for HTTP/HTTPS servers...${NC}"
    cat $domain/sources/all.txt | httprobe | tee $domain/result/httpx/httpx.txt
    echo -e "${GREEN}[✓] HTTP probing completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Takeover check
check_takeover() {
    echo -e "\n${BLUE}[+] Checking for potential takeovers...${NC}"
    wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O /root/hades/fingerprints.json
    subjack -w $domain/result/httpx/httpx.txt \
            -t 100 \
            -timeout 30 \
            -ssl \
            -c /root/hades/fingerprints.json \
            -v 3 >> $domain/result/takeover/takeover.txt
    echo -e "${GREEN}[✓] Takeover check completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"

    # Load credentials
    token=$(cat telegram_token.txt)
    chat_id=$(cat telegram_chat_id.txt)

    # Send initial message
    message="🔍 Scan completed for domain: $domain\n📤 Sending results..."
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

    echo -e "${GREEN}[✓] All results have been sent to Telegram${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    check_waf
    enumerate_domains
    check_http
    check_takeover
    send_to_telegram
    echo -e "\n${GREEN}[✓] Scan completed successfully!${NC}\n"
}

# Run the script
main
