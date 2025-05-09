#!/bin/bash

# Colors
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

# Progress bar configuration
BAR_WIDTH=50
BAR_CHAR_DONE="#"
BAR_CHAR_TODO="-"
BRACKET_DONE="["
BRACKET_TODO="]"

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

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "Mass Assessment"
    echo -e "${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    clear
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Mass Assessment Scanner          ${NC}"
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

# Setup workspace
setup_workspace() {
    echo -e "\n${BLUE}[+] Setting up workspace...${NC}"
    mkdir -p "$workspace"/{sources,result/{nuclei/{low,medium,high,critical},httpx,exploit}}
    echo -e "${GREEN}[✓] Workspace created${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    if command -v wafw00f &> /dev/null; then
        wafw00f "$domain" | tee "$workspace/result/waf_detection.txt"
    else
        echo -e "${YELLOW}[!] wafw00f not found - performing basic WAF check${NC}"
        curl -sI "https://$domain" | grep -i "WAF" | tee "$workspace/result/waf_detection.txt"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Domain enumeration
enumerate_domain() {
    echo -e "\n${BLUE}[+] Starting Domain Enumeration...${NC}"
    
    # Run Subfinder
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    if command -v subfinder &> /dev/null; then
        subfinder -d "$domain" -o "$workspace/sources/subfinder.txt"
        subfinder_count=$(wc -l < "$workspace/sources/subfinder.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Subfinder found $subfinder_count subdomains${NC}"
    else
        echo -e "${RED}[!] Subfinder not found${NC}"
    fi
    
    # Run Assetfinder
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    if command -v assetfinder &> /dev/null; then
        assetfinder -subs-only "$domain" | tee "$workspace/sources/assetfinder.txt"
        assetfinder_count=$(wc -l < "$workspace/sources/assetfinder.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Assetfinder found $assetfinder_count subdomains${NC}"
    else
        echo -e "${RED}[!] Assetfinder not found${NC}"
    fi
    
    # Combine results
    cat "$workspace/sources/"*.txt 2>/dev/null | sort -u > "$workspace/sources/all.txt"
    total_domains=$(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Total unique subdomains: $total_domains${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    if command -v httprobe &> /dev/null; then
        cat "$workspace/sources/all.txt" | httprobe | tee "$workspace/result/httpx/httpx.txt"
        live_hosts=$(wc -l < "$workspace/result/httpx/httpx.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $live_hosts live hosts${NC}"
    else
        echo -e "${RED}[!] httprobe not found${NC}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Nuclei scan
run_nuclei() {
    echo -e "\n${BLUE}[+] Running Nuclei vulnerability scan...${NC}"
    
    if ! command -v nuclei &> /dev/null; then
        echo -e "${RED}[!] nuclei not found${NC}"
        return 1
    fi
    
    if [[ ! -f "$workspace/result/httpx/httpx.txt" ]]; then
        echo -e "${RED}[!] No live hosts found to scan${NC}"
        return 1
    fi
    
    echo -e "${MAGENTA}[*] Updating nuclei templates...${NC}"
    nuclei -ut
    
    echo -e "${MAGENTA}[*] Starting vulnerability scan...${NC}"
    
    # Run nuclei for each severity level
    for severity in low medium high critical; do
        echo -e "${YELLOW}[*] Scanning for $severity severity vulnerabilities...${NC}"
        nuclei -l "$workspace/result/httpx/httpx.txt" \
               -severity "$severity" \
               -o "$workspace/result/nuclei/${severity}/findings.txt"
        
        count=$(wc -l < "$workspace/result/nuclei/${severity}/findings.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $count $severity severity issues${NC}"
    done
    
    echo -e "${GREEN}[✓] Nuclei scan completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Generate summary report
generate_report() {
    echo -e "\n${BLUE}[+] Generating summary report...${NC}"
    
    report_file="$workspace/result/assessment_report.txt"
    
    {
        echo "Security Assessment Report"
        echo "========================="
        echo "Date: $(date)"
        echo "Target Domain: $domain"
        echo ""
        echo "Scan Statistics:"
        echo "---------------"
        echo "Total Subdomains: $(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")"
        echo "Live Hosts: $(wc -l < "$workspace/result/httpx/httpx.txt" 2>/dev/null || echo "0")"
        echo ""
        echo "Vulnerability Summary:"
        echo "--------------------"
        echo "Critical Issues: $(wc -l < "$workspace/result/nuclei/critical/findings.txt" 2>/dev/null || echo "0")"
        echo "High Issues: $(wc -l < "$workspace/result/nuclei/high/findings.txt" 2>/dev/null || echo "0")"
        echo "Medium Issues: $(wc -l < "$workspace/result/nuclei/medium/findings.txt" 2>/dev/null || echo "0")"
        echo "Low Issues: $(wc -l < "$workspace/result/nuclei/low/findings.txt" 2>/dev/null || echo "0")"
        echo ""
        echo "Detailed Findings:"
        echo "-----------------"
        for severity in critical high medium low; do
            if [[ -f "$workspace/result/nuclei/${severity}/findings.txt" ]]; then
                echo ""
                echo "$severity Severity Findings:"
                echo "-------------------------"
                cat "$workspace/result/nuclei/${severity}/findings.txt"
            fi
        done
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
        
        # Count vulnerabilities by severity
        critical_count=$(wc -l < "$workspace/result/nuclei/critical/findings.txt" 2>/dev/null || echo "0")
        high_count=$(wc -l < "$workspace/result/nuclei/high/findings.txt" 2>/dev/null || echo "0")
        medium_count=$(wc -l < "$workspace/result/nuclei/medium/findings.txt" 2>/dev/null || echo "0")
        low_count=$(wc -l < "$workspace/result/nuclei/low/findings.txt" 2>/dev/null || echo "0")
        
        message="🔍 Security Assessment completed for: $domain
📊 Summary:
• Total Subdomains: $(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")
• Live Hosts: $(wc -l < "$workspace/result/httpx/httpx.txt" 2>/dev/null || echo "0")

🎯 Vulnerabilities found:
• Critical: $critical_count
• High: $high_count
• Medium: $medium_count
• Low: $low_count

📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress tracking
        total_files=$(find "$workspace" -type f | wc -l)
        current=0
        
        find "$workspace" -type f | while read -r file; do
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
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    setup_workspace
    check_waf
    enumerate_domain
    probe_http
    run_nuclei
    generate_report
    send_to_telegram
    echo -e "\n${GREEN}[✓] Security assessment completed successfully!${NC}\n"
}

# Run the script
main