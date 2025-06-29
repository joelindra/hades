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
}

# Input target function
input_target() {
    clear
    echo -e "${BLUE}👽 Mass Server Domain Autoscanner${NC}"
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
        workspace="$input"  # Set workspace variable
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
        wafw00f "$workspace" | tee "$workspace/result/waf_detection.txt"
    else
        echo -e "${YELLOW}[!] wafw00f not found - performing basic WAF check${NC}"
        curl -sI "https://$workspace" | grep -i "WAF" | tee "$workspace/result/waf_detection.txt"
    fi
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# workspace enumeration
enumerate_workspace() {
    echo -e "\n${BLUE}[+] Starting workspace Enumeration...${NC}"
    
    # Run Subfinder
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    if command -v subfinder &> /dev/null; then
        subfinder -d "$workspace" -o "$workspace/sources/subfinder.txt"
        subfinder_count=$(wc -l < "$workspace/sources/subfinder.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Subfinder found $subfinder_count subworkspaces${NC}"
    else
        echo -e "${RED}[!] Subfinder not found${NC}"
    fi
    
    # Run Assetfinder
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    if command -v assetfinder &> /dev/null; then
        assetfinder -subs-only "$workspace" | tee "$workspace/sources/assetfinder.txt"
        assetfinder_count=$(wc -l < "$workspace/sources/assetfinder.txt" 2>/dev/null || echo "0")
        echo -e "${GREEN}[✓] Assetfinder found $assetfinder_count subworkspaces${NC}"
    else
        echo -e "${RED}[!] Assetfinder not found${NC}"
    fi
    
    # Combine results
    cat "$workspace/sources/"*.txt 2>/dev/null | sort -u > "$workspace/sources/all.txt"
    total_workspaces=$(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Total unique subworkspaces: $total_workspaces${NC}"
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
        echo "Target workspace: $workspace"
        echo ""
        echo "Scan Statistics:"
        echo "---------------"
        echo "Total Subworkspaces: $(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")"
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
    echo -e "\n${BLUE}[+] Preparing to send results to Telegram...${NC}"
    if ! command -v curl &> /dev/null || ! command -v zip &> /dev/null; then
        echo -e "${RED}[!] 'curl' and 'zip' are required but not installed.${NC}"
        return 1
    fi

    if [[ ! -f "telegram_token.txt" || ! -f "telegram_chat_id.txt" ]]; then
        echo -e "${RED}[!] Telegram credentials (telegram_token.txt, telegram_chat_id.txt) not found.${NC}"
        return 1
    fi

    local token=$(<"telegram_token.txt")
    local chat_id=$(<"telegram_chat_id.txt")
    local result_dir="$workspace/result"

    local message
    message=$(printf "🔍 *Autoscanning Scan Completed for:* \`%s\`\n\n" "$workspace"
    printf "📊 *Summary:*\n"
    printf " • Total URLs: \`%s\`\n" "$(wc -l < "$result_dir/wayback/wayback.txt" 2>/dev/null || echo 0)"
    printf " • Valid URLs: \`%s\`\n" "$(wc -l < "$result_dir/wayback/valid.txt" 2>/dev/null || echo 0)"
    printf " • Potential Finding: \`%s\`\n\n" "$(wc -l < "$workspace/result/nuclei/${severity}/findings.txt" 2>/dev/null || echo 0)"
    printf "📤 Detailed results are attached in the zip file."
    )

    # Kirim pesan ringkasan
    echo -e "${BLUE}[*] Sending summary message...${NC}"
    curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
        -d chat_id="$chat_id" \
        -d text="$message" \
        -d parse_mode="Markdown" > /dev/null

    # 3. Arsipkan Hasil dan Kirim
    if [ -d "$result_dir" ] && [ "$(ls -A "$result_dir")" ]; then
        local archive_name="results-$(basename "$workspace")-$(date +%F).zip"
        
        echo -e "${BLUE}[*] Creating results archive: ${archive_name}${NC}"
        # Opsi -j (junk paths) agar file tidak dalam folder saat di-zip
        zip -r -j "$archive_name" "$result_dir" > /dev/null

        echo -e "${BLUE}[*] Uploading archive...${NC}"
        curl -s -X POST "https://api.telegram.org/bot$token/sendDocument" \
            -F chat_id="$chat_id" \
            -F document=@"$archive_name" \
            -F caption="All scan results for $workspace" > /dev/null
        
        rm "$archive_name" # Hapus file zip setelah dikirim
    else
        echo -e "${YELLOW}[!] No result files found to archive in '$result_dir'.${NC}"
    fi
    
    echo -e "${GREEN}[✓] Process completed. Results sent to Telegram.${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    setup_workspace
    check_waf
    enumerate_workspace
    probe_http
    run_nuclei
    generate_report
    send_to_telegram
    echo -e "\n${GREEN}[✓] Security assessment completed successfully!${NC}\n"
}

# Run the script
main