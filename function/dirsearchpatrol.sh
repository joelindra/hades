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
    figlet -w 100 -f small "Dirsearch Patrol"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced Directory Enumeration Tool${NC}"
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
    wafw00f "$domain"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Domain enumeration
enumerate_domain() {
    echo -e "\n${BLUE}[+] Starting Domain Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p "$domain"/{sources,result/{takeover,httpx},reports}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$domain" -o "$domain/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$domain/sources/subfinder.txt")
    echo -e "${GREEN}[✓] Subfinder found ${subfinder_count} subdomains${NC}"
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$domain" | tee "$domain/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$domain/sources/assetfinder.txt")
    echo -e "${GREEN}[✓] Assetfinder found ${assetfinder_count} subdomains${NC}"
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat "$domain/sources/"*.txt > "$domain/sources/all.txt"
    total_domains=$(wc -l < "$domain/sources/all.txt")
    echo -e "${GREEN}[✓] Total unique subdomains: ${total_domains}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    cat $domain/sources/all.txt | httprobe | tee $domain/result/httpx/httpx.txt
    
    total_live=$(wc -l < "$domain/result/httpx/httpx.txt")
    echo -e "${GREEN}[✓] Found ${total_live} live hosts${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}


# Run Dirsearch on targets
run_dirsearch_patrol() {
    echo -e "\n${BLUE}[+] Starting Dirsearch Patrol...${NC}"
    
    total_targets=$(wc -l < "$domain/result/httpx/httpx.txt")
    current=0
    found_dirs=0
    
    while IFS= read -r target; do
        ((current++))
        echo -e "\n${YELLOW}[*] Scanning target ($current/$total_targets): $target${NC}"
        
        output_file="$domain/reports/${target//\//_}_dirsearch_report.txt"
        
        dirsearch -u "$target" \
                 -t 150 \
                 -x 403,404,401,500,429 \
                 -i 200,302,301 \
                 --random-agent \
                 -o "$output_file"
        
        # Count found directories
        if [[ -f "$output_file" ]]; then
            dirs_found=$(grep -c "200\|301\|302" "$output_file")
            ((found_dirs+=dirs_found))
            echo -e "${GREEN}[✓] Found $dirs_found directories for $target${NC}"
        fi
    done < "$domain/sources/all.txt"
    
    echo -e "\n${GREEN}[✓] Dirsearch completed! Total directories found: $found_dirs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Count total directories found
        total_dirs=$(find "$domain/reports" -type f -exec grep -c "200\|301\|302" {} \; | awk '{sum+=$1} END{print sum}')
        
        # Send summary message
        message="🔍 Dirsearch Patrol completed for: $domain

📊 Summary:
• Subdomains scanned: $(wc -l < "$domain/sources/all.txt")
• Total directories found: $total_dirs
• Report files generated: $(find "$domain/reports" -type f | wc -l)

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
    run_dirsearch_patrol
    send_to_telegram
    echo -e "\n${GREEN}[✓] Dirsearch patrol completed successfully!${NC}\n"
}

# Run the script
main
