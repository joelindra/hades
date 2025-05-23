#!/bin/bash

# Colors
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "Mass Auto Reconnaisance"
    echo -e "${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    clear
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Mass Auto Reconnaisance         ${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════╝${NC}\n"
    
    while true; do
        echo -e "${YELLOW}[?] Masukkan workspace target ${NC}(contoh: example.com)"
        echo -e "${YELLOW}[?] Ketik 'quit' untuk keluar${NC}"
        echo -ne "\n${GREEN}[+] Target workspace: ${NC}"
        read -r input
        
        # Validasi input
        if [[ -z "$input" ]]; then
            echo -e "\n${RED}[!] Error: workspace tidak boleh kosong!${NC}"
            sleep 1
            continue
        elif [[ "$input" == "quit" ]]; then
            echo -e "\n${YELLOW}[!] Keluar dari program...${NC}"
            exit 0
        elif ! [[ "$input" =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
            echo -e "\n${RED}[!] Error: Format workspace tidak valid!${NC}"
            sleep 1
            continue
        fi
        
        # Jika validasi berhasil
        echo -e "\n${GREEN}[✓] workspace target valid: $input${NC}"
        echo -e "${BLUE}[*] Memulai pemindaian...${NC}\n"
        sleep 1
        workspace="$input"  # Set workspace variable
        break
    done
    return 0
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f "$workspace"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# workspace enumeration
enumerate_workspace() {
    echo -e "\n${BLUE}[+] Starting workspace Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p "$workspace"/{sources,result/{nuclei,wayback,httpx,exploit,js,gf}}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$workspace" -o "$workspace/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$workspace/sources/subfinder.txt")
    echo -e "${GREEN}[✓] Subfinder found ${subfinder_count} subworkspaces${NC}"
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$workspace" | tee "$workspace/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$workspace/sources/assetfinder.txt")
    echo -e "${GREEN}[✓] Assetfinder found ${assetfinder_count} subworkspaces${NC}"
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat "$workspace/sources/"*.txt > "$workspace/sources/all.txt"
    total_workspaces=$(wc -l < "$workspace/sources/all.txt")
    echo -e "${GREEN}[✓] Total unique subworkspaces: ${total_workspaces}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# HTTP probe
probe_http() {
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    
    # Probe hosts dan simpan hasil sementara
    temp_file=$(mktemp)
    cat "$workspace/sources/all.txt" | httprobe | tee "$temp_file"
    
    # Deduplikasi: prioritaskan HTTPS daripada HTTP
    echo -e "${YELLOW}[+] Removing duplicates (prioritizing HTTPS)...${NC}"
    
    # Ekstrak workspace unik dan tentukan protokol terbaik
    awk -F'://' '{
        workspace = $2
        protocol = $1
        
        # Jika workspace belum ada atau protokol saat ini adalah https
        if (!(workspace in workspaces) || protocol == "https") {
            workspaces[workspace] = protocol "://" workspace
        }
    }
    END {
        for (d in workspaces) {
            print workspaces[d]
        }
    }' "$temp_file" | sort > "$workspace/result/httpx/httpx.txt"
    
    # Hapus file temporary
    rm -f "$temp_file"
    
    total_live=$(wc -l < "$workspace/result/httpx/httpx.txt")
    echo -e "${GREEN}[✓] Found ${total_live} live hosts (after deduplication)${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat "$workspace/result/httpx/httpx.txt" | waybackurls | anew "$workspace/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$workspace/result/wayback/wayback-tmp.txt" | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$workspace/result/wayback/wayback.txt"
    
    rm "$workspace/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$workspace/result/wayback/wayback.txt")
    echo -e "${GREEN}[✓] Found ${total_urls} unique URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    ffuf -c -u "FUZZ" -w "$workspace/result/wayback/wayback.txt" -of csv -o "$workspace/result/wayback/valid-tmp.txt"
    
    cat "$workspace/result/wayback/valid-tmp.txt" | grep http | awk -F "," '{print $1}' >> "$workspace/result/wayback/valid.txt"
    rm "$workspace/result/wayback/valid-tmp.txt"
    
    valid_urls=$(wc -l < "$workspace/result/wayback/valid.txt")
    echo -e "${GREEN}[✓] Validated ${valid_urls} URLs${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running pattern matching...${NC}"
    
    # Define patterns with descriptions
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
        ["takeovers"]="workspace Takeovers"
        ["cors"]="CORS Misconfig"
        ["s3-buckets"]="S3 Buckets"
    )
    
    total_patterns=${#patterns[@]}
    current=0
    
    for pattern in "${!patterns[@]}"; do
        ((current++))
        echo -e "${MAGENTA}[*] ($current/$total_patterns) Checking for ${patterns[$pattern]}...${NC}"
        gf "$pattern" "$workspace/result/wayback/valid.txt" | tee "$workspace/result/gf/${pattern}.txt"
        count=$(wc -l < "$workspace/result/gf/${pattern}.txt")
        echo -e "${GREEN}[✓] Found ${count} potential ${patterns[$pattern]} endpoints${NC}"
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Send initial message with summary
        message="🔍 Reconnaissance completed for: $workspace
📊 Summary:
• Subworkspaces found: $(wc -l < "$workspace/sources/all.txt")
• Live hosts: $(wc -l < "$workspace/result/httpx/httpx.txt")
• Unique URLs: $(wc -l < "$workspace/result/wayback/wayback.txt")
• Valid URLs: $(wc -l < "$workspace/result/wayback/valid.txt")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files
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
    check_waf
    enumerate_workspace
    probe_http
    collect_wayback
    validate_urls
    run_gf_patterns
    send_to_telegram
    echo -e "\n${GREEN}[✓] Reconnaissance completed successfully!${NC}\n"
}

# Run the script
main