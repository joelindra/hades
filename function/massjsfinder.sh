#!/bin/bash

# Colors
MAGENTA='\e[1;35m'
NC='\e[0m' # No Color
BLUE='\e[1;34m'
GREEN='\e[1;32m'
RED='\e[1;31m'
YELLOW='\e[1;33m'
CYAN='\e[1;36m'

# Progress bar configuration
BAR_WIDTH=50
BAR_CHAR_DONE="#"
BAR_CHAR_TODO="-"
BRACKET_DONE="["
BRACKET_TODO="]"

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "Mass JS Finder"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced JavaScript File Discovery Tool${NC}"
    echo -e "${MAGENTA}[*] Version: 1.0${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Progress bar function
display_progress() {
    local current=$1
    local total=$2
    local title=$3
    local percent=$((current * 100 / total))
    local done=$((percent * BAR_WIDTH / 100))
    local todo=$((BAR_WIDTH - done))

    printf "\r${YELLOW}[*] %s: ${BRACKET_DONE}" "${title}"
    printf "%${done}s" | tr " " "${BAR_CHAR_DONE}"
    printf "%${todo}s${BRACKET_TODO} %3d%%" | tr " " "${BAR_CHAR_TODO}"
    echo -en " ($current/$total)${NC}"
}

# Input target function
input_target() {
    echo -e "\n${BLUE}[+] Target Configuration${NC}"
    read -p $'\e[1;35m🌐 Enter the domain or file path: \e[0m' input
    echo -e "${GREEN}[*] Input received: $input${NC}"
    sleep 1
}

# Create directory structure
setup_directories() {
    local domain=$1
    echo -e "\n${BLUE}[+] Setting up workspace for ${domain}...${NC}"
    mkdir -p "$domain"/{sources,result/{nuclei,wayback,httpx,exploit,js}}
    echo -e "${GREEN}[✓] Directory structure created${NC}"
}

# Subdomain enumeration
run_subdomain_enum() {
    local domain=$1
    echo -e "\n${BLUE}[+] Starting subdomain enumeration for ${domain}...${NC}"
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$domain" -o "$domain/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$domain/sources/subfinder.txt")
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$domain" | tee "$domain/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$domain/sources/assetfinder.txt")
    
    cat "$domain/sources/"*.txt > "$domain/sources/all.txt"
    total_domains=$(wc -l < "$domain/sources/all.txt")
    
    echo -e "${GREEN}[✓] Found: Subfinder ($subfinder_count), Assetfinder ($assetfinder_count), Total unique ($total_domains)${NC}"
}

# HTTP probe function
probe_http() {
    local domain=$1
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    cat "$domain/sources/all.txt" | httprobe | tee "$domain/result/httpx/httpx.txt"
    live_hosts=$(wc -l < "$domain/result/httpx/httpx.txt")
    echo -e "${GREEN}[✓] Found $live_hosts live hosts${NC}"
}

# Wayback data collection
collect_wayback() {
    local domain=$1
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat "$domain/result/httpx/httpx.txt" | waybackurls | anew "$domain/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$domain/result/wayback/wayback-tmp.txt" | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$domain/result/wayback/wayback.txt"
    
    rm "$domain/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$domain/result/wayback/wayback.txt")
    echo -e "${GREEN}[✓] Found $total_urls unique URLs${NC}"
}

# URL validation
validate_urls() {
    local domain=$1
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    
    cat "$domain/result/wayback/wayback.txt" | \
        ffuf -c -u "FUZZ" -w - -of csv -o "$domain/result/wayback/valid-tmp.txt" -t 100 -rate 1000
    
    cat "$domain/result/wayback/valid-tmp.txt" | grep http | awk -F "," '{print $1}' >> "$domain/result/wayback/valid.txt"
    rm "$domain/result/wayback/valid-tmp.txt"
    
    valid_count=$(wc -l < "$domain/result/wayback/valid.txt")
    echo -e "${GREEN}[✓] Validated $valid_count URLs${NC}"
}

# JavaScript file discovery
find_js_files() {
    local domain=$1
    echo -e "\n${BLUE}[+] Searching for JavaScript files...${NC}"
    
    cat "$domain/result/wayback/valid.txt" | grep "\.js$" | sort -u > "$domain/result/js/js.txt"
    js_count=$(wc -l < "$domain/result/js/js.txt")
    echo -e "${GREEN}[✓] Found $js_count JavaScript files${NC}"
    
    echo -e "${MAGENTA}[*] Analyzing JavaScript files for secrets...${NC}"
    total_js=$(wc -l < "$domain/result/js/js.txt")
    current=0
    
    while IFS= read -r url; do
        ((current++))
        display_progress "$current" "$total_js" "Analyzing JS files"
        secretfinder.py -i "$url" -o cli >> "$domain/result/js/secret.txt" 2>/dev/null
    done < "$domain/result/js/js.txt"
    echo -e "\n${GREEN}[✓] JavaScript analysis completed${NC}"
}

# Send results to Telegram
send_to_telegram() {
    local domain=$1
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Send summary message
        message="🔍 JS Finder scan completed for: $domain
📊 Summary:
• Subdomains found: $(wc -l < "$domain/sources/all.txt")
• Live hosts: $(wc -l < "$domain/result/httpx/httpx.txt")
• JavaScript files: $(wc -l < "$domain/result/js/js.txt")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress
        total_files=$(find "$domain" -type f | wc -l)
        current=0
        
        find "$domain" -type f | while read file; do
            ((current++))
            display_progress "$current" "$total_files" "Sending files"
            curl -s -F chat_id="$chat_id" \
                 -F document=@"$file" \
                 "https://api.telegram.org/bot$token/sendDocument" > /dev/null 2>&1
        done
        echo -e "\n${GREEN}[✓] Results sent to Telegram${NC}"
    else
        echo -e "${RED}[!] Telegram credentials not found${NC}"
    fi
}

# Process single domain
process_domain() {
    local domain=$1
    echo -e "\n${CYAN}[+] Processing domain: $domain${NC}"
    setup_directories "$domain"
    run_subdomain_enum "$domain"
    probe_http "$domain"
    collect_wayback "$domain"
    validate_urls "$domain"
    find_js_files "$domain"
    send_to_telegram "$domain"
    echo -e "${GREEN}[✓] Processing completed for $domain${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    
    if [[ -f $input ]]; then
        echo -e "${BLUE}[+] Processing domains from file: $input${NC}"
        total_domains=$(wc -l < "$input")
        current=0
        
        while IFS= read -r domain; do
            if [[ ! -z "$domain" && "$domain" != "#"* ]]; then
                ((current++))
                display_progress "$current" "$total_domains" "Processing domains"
                process_domain "$domain" &
            fi
        done < "$input"
        wait
        echo -e "\n${GREEN}[✓] All domains processed successfully!${NC}\n"
    else
        process_domain "$input"
    fi
}

# Run the script
main