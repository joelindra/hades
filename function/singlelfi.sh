#!/bin/bash

# Colors
MAGENTA='\e[1;35m'
NC='\e[0m' # No Color
BLUE='\e[1;34m'
GREEN='\e[1;32m'
RED='\e[1;31m'
YELLOW='\e[1;33m'

# Banner function with enhanced styling
display_banner() {
    clear
    echo -e "${BLUE}"
    if command -v figlet &> /dev/null; then
        figlet -w 100 -f small "LFI Scanner Pro"
    else
        echo "===================="
        echo "  LFI Scanner Pro"
        echo "===================="
    fi
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced Local File Inclusion Scanner Pro${NC}"
    echo -e "${MAGENTA}[*] Version: 2.0${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Target configuration function
input_target() {
    echo -e "\n${BLUE}[+] Target Configuration${NC}"
    read -p $'\e[1;35m🌐 Enter the domain you want to explore: \e[0m' domain
    echo -e "${GREEN}[*] Target set to: $domain${NC}"
    sleep 1
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    if command -v wafw00f &> /dev/null; then
        wafw00f $domain
    else
        echo -e "${YELLOW}[!] wafw00f not found - performing basic WAF check${NC}"
        curl -sI "https://$domain" | grep -i "WAF"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Create directory structure and collect wayback data
setup_wayback() {
    echo -e "\n${BLUE}[+] Setting up workspace and collecting URLs...${NC}"
    workspace="${domain}"
    mkdir -p "$workspace"/{sources,result/{gf,wayback,lfi}}
    
    echo -e "${MAGENTA}[*] Fetching URLs from Wayback Machine...${NC}"
    if command -v waybackurls &> /dev/null; then
        echo "https://$domain/" | waybackurls | tee "$workspace/result/wayback/wayback-tmp.txt" 
    else
        echo -e "${YELLOW}[!] waybackurls not found - skipping Wayback Machine data collection${NC}"
        touch "$workspace/result/wayback/wayback-tmp.txt"
    fi
    
    if [[ -f "$workspace/result/wayback/wayback-tmp.txt" ]]; then
        cat "$workspace/result/wayback/wayback-tmp.txt" | \
            grep -ivE "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
            sed 's/:80//g;s/:443//g' | \
            sort -u > "$workspace/result/wayback/wayback.txt"
        
        rm "$workspace/result/wayback/wayback-tmp.txt"
    fi
    
    echo -e "${GREEN}[✓] URL collection completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    if [[ -f "$workspace/result/wayback/wayback.txt" ]]; then
        if command -v ffuf &> /dev/null; then
            cat "$workspace/result/wayback/wayback.txt" | \
                ffuf -c -u "FUZZ" -w - -of csv -o "$workspace/result/wayback/valid-tmp.txt" \
                -t 100 -rate 1000
            
            if [[ -f "$workspace/result/wayback/valid-tmp.txt" ]]; then
                cat "$workspace/result/wayback/valid-tmp.txt" | grep http | awk -F "," '{print $1}' > "$workspace/result/wayback/valid.txt"
                rm "$workspace/result/wayback/valid-tmp.txt"
            fi
        else
            echo -e "${YELLOW}[!] ffuf not found - copying all URLs as valid${NC}"
            cp "$workspace/result/wayback/wayback.txt" "$workspace/result/wayback/valid.txt"
        fi
    else
        echo -e "${RED}[!] No URLs found to validate${NC}"
        touch "$workspace/result/wayback/valid.txt"
    fi
    
    echo -e "${GREEN}[✓] URL validation completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running pattern matching...${NC}"
    
    if ! command -v gf &> /dev/null; then
        echo -e "${RED}[!] gf not found - skipping pattern matching${NC}"
        return
    fi
    
    patterns=("lfi" "rce" "ssrf" "sqli" "xss" "idor" "debug_logic")
    
    for pattern in "${patterns[@]}"; do
        echo -e "${MAGENTA}[*] Checking for $pattern...${NC}"
        gf "$pattern" "$workspace/result/wayback/valid.txt" 2>/dev/null | tee "$workspace/result/gf/${pattern}.txt"
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Load payloads from value.txt
load_payloads() {
    CONFIG_FILE="value.txt"
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${BLUE}[+] Loading payloads from value.txt...${NC}"
        mapfile -t payloads < "$CONFIG_FILE"
        total_payloads=${#payloads[@]}
        echo -e "${GREEN}[✓] Loaded $total_payloads payloads${NC}"
        echo -e "${MAGENTA}[*] Payload examples:${NC}"
        for ((i=0; i<3 && i<total_payloads; i++)); do
            echo -e "${YELLOW}    - ${payloads[$i]}${NC}"
        done
        if [ $total_payloads -gt 3 ]; then
            remaining=$((total_payloads-3))
            echo -e "${YELLOW}    ... and $remaining more${NC}"
        fi
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
    
    # Extract current parameter value
    if echo "$url" | grep -q "="; then
        original_value=$(echo "$url" | cut -d'=' -f2- | cut -d'&' -f1)
        base_url="${url/${original_value}/}"
        
        echo -e "${BLUE}[*] Testing URL: $url${NC}"
        echo -e "${MAGENTA}[*] Original value: $original_value${NC}"
        
        # Test each payload
        for payload in "${payloads[@]}"; do
            # Skip empty lines
            [[ -z "$payload" ]] && continue
            
            # Remove any whitespace/carriage returns
            payload=$(echo "$payload" | tr -d '\r' | xargs)
            
            # Create test URL by replacing original value with payload
            test_url="${base_url}${payload}"
            echo -e "${YELLOW}[*] Testing with payload: $payload${NC}"
            
            # Send request and check response
            response=$(curl -s -L "$test_url" -H "User-Agent: Mozilla/5.0" --max-time 5)
            
            # Check specifically for root:x:0:0
            if echo "$response" | grep -q "root:x:0:0"; then
                echo -e "${RED}[!] VULNERABLE - Found root:x:0:0 in response${NC}"
                echo "[VULNERABLE] $test_url - root:x:0:0 found" >> "$workspace/result/lfi/vulnerable.txt"
                
                # Save the full response
                mkdir -p "$workspace/result/lfi/responses"
                response_file="$workspace/result/lfi/responses/$(echo "$test_url" | md5sum | cut -d' ' -f1).txt"
                echo "URL: $test_url" > "$response_file"
                echo "Payload: $payload" >> "$response_file"
                echo "Response:" >> "$response_file"
                echo "$response" >> "$response_file"
                echo -e "${MAGENTA}[*] Full response saved to: $response_file${NC}"
            else
                echo -e "${GREEN}[✓] NOT VULNERABLE${NC}"
            fi
        done
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
    
    # Create directories for results
    mkdir -p "$workspace/result/lfi/responses"
    
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
        echo ""
        echo "Note: Detailed responses for vulnerable URLs can be found in the 'responses' directory"
    } > "$report_file"
    
    echo -e "${GREEN}[✓] Report generated: $report_file${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram if configured
send_to_telegram() {
    if [[ -n "${TELEGRAM_TOKEN}" && -n "${TELEGRAM_CHAT_ID}" ]]; then
        echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
        
        message="🔍 LFI scan completed for domain: $domain"
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
             -d chat_id="${TELEGRAM_CHAT_ID}" \
             -d text="$message" > /dev/null 2>&1
        
        if [[ -f "$workspace/result/lfi/vulnerable.txt" ]]; then
            curl -s -F chat_id="${TELEGRAM_CHAT_ID}" \
                 -F document=@"$workspace/result/lfi/vulnerable.txt" \
                 "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendDocument" > /dev/null 2>&1
            
            curl -s -F chat_id="${TELEGRAM_CHAT_ID}" \
                 -F document=@"$workspace/result/lfi/summary_report.txt" \
                 "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendDocument" > /dev/null 2>&1
        fi
        
        echo -e "${GREEN}[✓] Results sent to Telegram${NC}"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    fi
}

# Cleanup function
cleanup() {
    if [[ -d "$workspace" ]]; then
        echo -e "\n${BLUE}[+] Cleaning up temporary files...${NC}"
        find "$workspace" -type f -empty -delete
        find "$workspace" -type d -empty -delete
        echo -e "${GREEN}[✓] Cleanup completed${NC}"
    fi
}

# Main execution
main() {
    display_banner
    input_target
    check_waf
    setup_wayback
    validate_urls
    run_gf_patterns
    load_payloads
    process_urls
    generate_report
    send_to_telegram
    cleanup
    
    # Final summary
    if [[ -f "$workspace/result/lfi/vulnerable.txt" ]]; then
        vuln_count=$(wc -l < "$workspace/result/lfi/vulnerable.txt")
        echo -e "\n${RED}[!] Found $vuln_count vulnerable URLs${NC}"
        echo -e "${YELLOW}[*] Check the summary report: $workspace/result/lfi/summary_report.txt${NC}"
    else
        echo -e "\n${GREEN}[✓] No vulnerabilities found${NC}"
    fi
    
    echo -e "\n${GREEN}[✓] LFI scan completed successfully!${NC}\n"
}

# Run the script
main
