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
}

# Input target function
input_target() {
    clear
    echo -e "${BLUE}👽 Single Domain Directory Patrol${NC}"
    echo ""
    
    while true; do
        echo -e "${YELLOW}[?] Masukkan domain target ${NC}(contoh: example.com)"
        echo -e "${YELLOW}[?] Ketik 'quit' untuk keluar${NC}"
        echo -ne "\n${GREEN}[+] Target domain: ${NC}"
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
        break
    done
    
    # Simpan workspace ke variable global
    TARGET_workspace="$input"
    return 0
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    echo -e "${MAGENTA}[*] Running WAF detection...${NC}"
    wafw00f "$TARGET_workspace"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# workspace enumeration
enumerate_workspace() {
    echo -e "\n${BLUE}[+] Starting workspace Enumeration...${NC}"
    
    # Create directory structure
    mkdir -p "$TARGET_workspace"/{sources,result/{takeover,httpx},reports}
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$TARGET_workspace" -o "$TARGET_workspace/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$TARGET_workspace/sources/subfinder.txt")
    echo -e "${GREEN}[✓] Subfinder found ${subfinder_count} subworkspaces${NC}"
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$TARGET_workspace" | tee "$TARGET_workspace/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$TARGET_workspace/sources/assetfinder.txt")
    echo -e "${GREEN}[✓] Assetfinder found ${assetfinder_count} subworkspaces${NC}"
    
    echo -e "${MAGENTA}[*] Combining results...${NC}"
    cat "$TARGET_workspace/sources/"*.txt > "$TARGET_workspace/sources/all.txt"
    total_workspaces=$(wc -l < "$TARGET_workspace/sources/all.txt")
    echo -e "${GREEN}[✓] Total unique subworkspaces: ${total_workspaces}${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

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

# Run Dirsearch on targets
run_dirsearch_patrol() {
    echo -e "\n${BLUE}[+] Starting Dirsearch Patrol...${NC}"
    
    total_targets=$(wc -l < "$TARGET_workspace/result/httpx/httpx.txt")
    current=0
    found_dirs=0
    
    while IFS= read -r target; do
        ((current++))
        echo -e "\n${YELLOW}[*] Scanning target ($current/$total_targets): $target${NC}"
        
        output_file="$TARGET_workspace/reports/${target//\//_}_dirsearch_report.txt"
        
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
    done < "$TARGET_workspace/result/httpx/httpx.txt"
    
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
        total_dirs=$(find "$TARGET_workspace/reports" -type f -exec grep -c "200\|301\|302" {} \; | awk '{sum+=$1} END{print sum}')
        
        # Send summary message
        message="🔍 Dirsearch Patrol completed for: $TARGET_workspace

📊 Summary:
• Subworkspaces scanned: $(wc -l < "$TARGET_workspace/sources/all.txt")
• Total directories found: $total_dirs
• Report files generated: $(find "$TARGET_workspace/reports" -type f | wc -l)

📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress
        total_files=$(find "$TARGET_workspace" -type f | wc -l)
        current=0
        
        find "$TARGET_workspace" -type f | while read -r file; do
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
    run_dirsearch_patrol
    send_to_telegram
    echo -e "\n${GREEN}[✓] Dirsearch patrol completed successfully!${NC}\n"
}

# Run the script
main