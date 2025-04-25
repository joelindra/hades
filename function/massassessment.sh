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
    figlet -w 100 -f small "Mass Assessment"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced Security Assessment Tool${NC}"
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
    echo -e "${MAGENTA}[*] Running WAF detection...${NC}"
    wafw00f $domain
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Domain enumeration
enumerate_domain() {
    echo -e "\n${BLUE}[+] Starting Domain Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p $domain/{sources,result/{nuclei,httpx,exploit}}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d $domain -o $domain/sources/subfinder.txt
    subfinder_count=$(wc -l < "$domain/sources/subfinder.txt")
    echo -e "${GREEN}[✓] Subfinder found ${subfinder_count} subdomains${NC}"
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
    assetfinder_count=$(wc -l < "$domain/sources/assetfinder.txt")
    echo -e "${GREEN}[✓] Assetfinder found ${assetfinder_count} subdomains${NC}"
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat $domain/sources/*.txt > $domain/sources/all.txt
    total_domains=$(wc -l < "$domain/sources/all.txt")
    echo -e "${GREEN}[✓] Total unique subdomains: ${total_domains}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    cat $domain/sources/all.txt | httprobe | tee $domain/result/httpx/httpx.txt
    live_hosts=$(wc -l < "$domain/result/httpx/httpx.txt")
    echo -e "${GREEN}[✓] Found ${live_hosts} live hosts${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Nuclei scan
run_nuclei() {
    echo -e "\n${BLUE}[+] Running Nuclei vulnerability scan...${NC}"
    echo -e "${MAGENTA}[*] Scanning for vulnerabilities (this may take a while)...${NC}"
    
    cat $domain/result/httpx/httpx.txt | \
        nuclei -severity low,medium,high,critical \
        -o $domain/result/nuclei/vuln.txt

    # Count vulnerabilities by severity
    low_count=$(grep -c "low" "$domain/result/nuclei/vuln.txt" || echo "0")
    medium_count=$(grep -c "medium" "$domain/result/nuclei/vuln.txt" || echo "0")
    high_count=$(grep -c "high" "$domain/result/nuclei/vuln.txt" || echo "0")
    critical_count=$(grep -c "critical" "$domain/result/nuclei/vuln.txt" || echo "0")
    
    echo -e "\n${YELLOW}[*] Vulnerability Summary:${NC}"
    echo -e "  ${GREEN}• Low: $low_count${NC}"
    echo -e "  ${YELLOW}• Medium: $medium_count${NC}"
    echo -e "  ${RED}• High: $high_count${NC}"
    echo -e "  ${RED}• Critical: $critical_count${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Count vulnerabilities
        low_count=$(grep -c "low" "$domain/result/nuclei/vuln.txt" || echo "0")
        medium_count=$(grep -c "medium" "$domain/result/nuclei/vuln.txt" || echo "0")
        high_count=$(grep -c "high" "$domain/result/nuclei/vuln.txt" || echo "0")
        critical_count=$(grep -c "critical" "$domain/result/nuclei/vuln.txt" || echo "0")
        
        # Send summary message
        message="🔍 Security Assessment completed for: $domain

📊 Summary:
• Subdomains found: $(wc -l < "$domain/sources/all.txt")
• Live hosts: $(wc -l < "$domain/result/httpx/httpx.txt")

🎯 Vulnerabilities found:
• Low: $low_count
• Medium: $medium_count
• High: $high_count
• Critical: $critical_count

📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress
        total_files=$(find "$domain" -type f | wc -l)
        current=0
        
        find "$domain" -type f | while read file; do
            ((current++))
            echo -e "${MAGENTA}[*] Sending file ($current/$total_files): $(basename $file)${NC}"
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
    run_nuclei
    send_to_telegram
    echo -e "\n${GREEN}[✓] Security assessment completed successfully!${NC}\n"
}

# Run the script
main