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

source "notifier.sh"

# Variabel global
workspace="$1"
workspace="./workspace/$workspace"
config_file="../config/config.json"

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
    echo -e "${BLUE}👽 Subworkspace Takeover Scanner          ${NC}"
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
    mkdir -p "$workspace"/{sources,result/{takeover,httpx}}
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
enumerate_workspaces() {
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
check_http() {
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

# Takeover check
check_takeover() {
    echo -e "\n${BLUE}[+] Initiating subworkspace takeover vulnerability scan...${NC}"
    
    # Create necessary directories
    mkdir -p "$workspace/result/takeover"
    mkdir -p "$workspace/configs"
    
    # Check for subjack
    if ! command -v subjack &> /dev/null; then
        echo -e "${YELLOW}[!] subjack not found. Installing...${NC}"
        go install github.com/haccer/subjack@latest
        if ! command -v subjack &> /dev/null; then
            echo -e "${RED}[!] Failed to install subjack. Aborting.${NC}"
            return 1
        fi
    fi

    # Download latest fingerprints
    echo -e "${MAGENTA}[*] Updating fingerprints...${NC}"
    wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O "$workspace/configs/subjack_fingerprints.json"
    
    if [[ ! -f "$workspace/configs/subjack_fingerprints.json" ]]; then
        echo -e "${RED}[!] Failed to download fingerprints. Aborting.${NC}"
        return 1
    fi
    
    if [[ -f "$workspace/result/httpx/httpx.txt" ]]; then
        input_file="$workspace/result/httpx/httpx.txt"
        
        echo -e "${MAGENTA}[*] Starting enhanced takeover detection...${NC}"
        
        # Run subjack with optimized settings
        echo -e "${YELLOW}[*] Running Subjack scanner with enhanced configuration...${NC}"
        subjack -w "$input_file" \
                -t 200 \
                -timeout 30 \
                -ssl \
                -c "$workspace/configs/subjack_fingerprints.json" \
                -v 3 \
                -o "$workspace/result/takeover/subjack_results.txt"

        # Check if scan produced results
        if [[ ! -f "$workspace/result/takeover/subjack_results.txt" ]]; then
            echo -e "${RED}[!] No results found from scan${NC}"
            return 1
        fi

        # Copy results to consolidated file
        cp "$workspace/result/takeover/subjack_results.txt" "$workspace/result/takeover/consolidated_results.txt"
        
        # Count results
        total_results=$(wc -l < "$workspace/result/takeover/consolidated_results.txt" 2>/dev/null || echo "0")

        # Enhanced output formatting
        echo -e "\n${GREEN}[✓] Scan Complete! Results Summary:${NC}"
        echo -e "${CYAN}└── Total Findings: $total_results${NC}"

        # Check for high-risk services with enhanced detection
        high_risk_services=(
            "s3.amazonaws.com:AWS S3 Bucket"
            "cloudfront.net:AWS CloudFront"
            "github.io:GitHub Pages"
            "herokuapp.com:Heroku"
            "azurewebsites.net:Azure Websites"
            "cloudapp.net:Azure Cloud App"
            "googleapis.com:Google Cloud"
            "elasticbeanstalk.com:AWS Elastic Beanstalk"
            "ghost.io:Ghost CMS"
            "firebaseapp.com:Firebase"
            "shopify.com:Shopify"
            "netlify.app:Netlify"
            "wordpress.com:WordPress"
            "statuspage.io:Statuspage"
            "squarespace.com:Squarespace"
            "zendesk.com:Zendesk"
            "surge.sh:Surge"
            "bitbucket.io:Bitbucket"
            "fastly.net:Fastly"
            "pantheonsite.io:Pantheon"
        )
        
        echo -e "\n${YELLOW}[*] Analyzing potential vulnerabilities...${NC}"
        found_high_risk=false
        
        for service in "${high_risk_services[@]}"; do
            service_workspace="${service%%:*}"
            service_name="${service#*:}"
            count=$(grep -i "$service_workspace" "$workspace/result/takeover/consolidated_results.txt" | wc -l)
            
            if [ $count -gt 0 ]; then
                found_high_risk=true
                echo -e "${RED}[!] Found $count potential $service_name ($service_workspace) takeover vulnerabilities!${NC}"
                echo -e "${MAGENTA}[*] Vulnerable subworkspaces:${NC}"
                grep -i "$service_workspace" "$workspace/result/takeover/consolidated_results.txt" | while read -r line; do
                    echo -e "${CYAN}    └── $line${NC}"
                done
            fi
        done

        if [ "$found_high_risk" = false ]; then
            echo -e "${GREEN}[✓] No high-risk services detected${NC}"
        fi

        # Generate enhanced HTML report
        echo -e "\n${MAGENTA}[*] Generating detailed HTML report...${NC}"
        cat << EOF > "$workspace/result/takeover/report.html"
<!DOCTYPE html>
<html>
<head>
    <title>Subworkspace Takeover Vulnerability Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .high-risk { 
            color: #d63031;
            font-weight: bold;
            background-color: #ffe3e3;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .finding { 
            margin: 10px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: #f8f9fa;
        }
        .summary {
            background-color: #e3f2fd;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            text-align: center;
        }
        .timestamp {
            color: #666;
            font-size: 0.9em;
            text-align: right;
            margin-top: 20px;
        }
        h1, h2 { 
            color: #2c3e50;
            border-bottom: 2px solid #eee;
            padding-bottom: 10px;
        }
        .service-section {
            margin: 20px 0;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
        }
        .service-name {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Subworkspace Takeover Vulnerability Report</h1>
        
        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Total Findings:</strong> $total_results</p>
            <p><strong>Scan Date:</strong> $(date)</p>
        </div>

        <h2>Detailed Findings</h2>
        <div id="findings">
EOF

        # Add findings by service
        for service in "${high_risk_services[@]}"; do
            service_workspace="${service%%:*}"
            service_name="${service#*:}"
            if grep -qi "$service_workspace" "$workspace/result/takeover/consolidated_results.txt"; then
                cat << EOF >> "$workspace/result/takeover/report.html"
            <div class="service-section">
                <div class="service-name">$service_name ($service_workspace)</div>
                $(grep -i "$service_workspace" "$workspace/result/takeover/consolidated_results.txt" | while read -r line; do
                    echo "<div class='finding high-risk'>$line</div>"
                done)
            </div>
EOF
            fi
        done

        # Add other findings
        cat << EOF >> "$workspace/result/takeover/report.html"
            <div class="service-section">
                <div class="service-name">Other Findings</div>
                $(cat "$workspace/result/takeover/consolidated_results.txt" | while read -r line; do
                    is_high_risk=false
                    for service in "${high_risk_services[@]}"; do
                        service_workspace="${service%%:*}"
                        if echo "$line" | grep -qi "$service_workspace"; then
                            is_high_risk=true
                            break
                        fi
                    done
                    if [ "$is_high_risk" = false ]; then
                        echo "<div class='finding'>$line</div>"
                    fi
                done)
            </div>
        </div>
        <div class="timestamp">Report generated on $(date)</div>
    </div>
</body>
</html>
EOF

    else
        echo -e "${RED}[!] No live hosts found to check${NC}"
        return 1
    fi
    
    echo -e "\n${BLUE}[+] Takeover scan completed. Reports generated:${NC}"
    echo -e "${CYAN}├── Main Results: $workspace/result/takeover/consolidated_results.txt${NC}"
    echo -e "${CYAN}└── HTML Report: $workspace/result/takeover/report.html${NC}"
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Generate summary report
generate_report() {
    echo -e "\n${BLUE}[+] Generating summary report...${NC}"
    
    report_file="$workspace/result/takeover/summary_report.txt"
    
    {
        echo "Subworkspace Takeover Scan Report"
        echo "=============================="
        echo "Date: $(date)"
        echo "Target workspace: $workspace"
        echo ""
        echo "Scan Statistics:"
        echo "---------------"
        echo "Total Subworkspaces: $(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")"
        echo "Live Hosts: $(wc -l < "$workspace/result/httpx/httpx.txt" 2>/dev/null || echo "0")"
        echo "Potential Takeovers: $(wc -l < "$workspace/result/takeover/results.txt" 2>/dev/null || echo "0")"
        echo ""
        echo "Findings:"
        echo "---------"
        if [[ -f "$workspace/result/takeover/results.txt" ]]; then
            cat "$workspace/result/takeover/results.txt"
        else
            echo "No potential takeovers found"
        fi
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
    message=$(printf "🔍 *Subdomain Takeover Scan Completed for:* \`%s\`\n\n" "$workspace"
    printf "📊 *Summary:*\n"
    printf " • Total URLs: \`%s\`\n" "$(wc -l < "$result_dir/wayback/wayback.txt" 2>/dev/null || echo 0)"
    printf " • Valid URLs: \`%s\`\n" "$(wc -l < "$result_dir/wayback/valid.txt" 2>/dev/null || echo 0)"
    printf " • Potential Takeover: \`%s\`\n\n" "$(wc -l < "$workspace/result/takeover/results.txt" 2>/dev/null || echo 0)"
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
    enumerate_workspaces
    check_http
    check_takeover
    generate_report
    send_to_telegram
    echo -e "\n${GREEN}[✓] Subworkspace Takeover scan completed successfully!${NC}\n"
}

# Run the script
main