#!/bin/bash

# Colors
MAGENTA='\033[1;35m'
NC='\033[0m' # No Color
BLUE='\033[1;34m'
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'

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
    figlet -w 100 -f small "Mass JS Files Finder"
    echo -e "${NC}"
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
    clear
    echo -e "\n${BLUE}╔════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          Mass JS Files Finder         ${NC}"
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

# Create directory structure
setup_directories() {
    local workspace="$1"
    echo -e "\n${BLUE}[+] Setting up workspace for ${workspace}...${NC}"
    mkdir -p "$workspace"/{sources,result/{nuclei,wayback,httpx,exploit,js}}
    echo -e "${GREEN}[✓] Directory structure created${NC}"
}

# Subworkspace enumeration
run_subworkspace_enum() {
    local workspace="$1"
    echo -e "\n${BLUE}[+] Starting subworkspace enumeration for ${workspace}...${NC}"
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$workspace" -o "$workspace/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$workspace/sources/subfinder.txt" 2>/dev/null || echo "0")
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$workspace" | tee "$workspace/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$workspace/sources/assetfinder.txt" 2>/dev/null || echo "0")
    
    cat "$workspace/sources/"*.txt 2>/dev/null | sort -u > "$workspace/sources/all.txt"
    total_workspaces=$(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}[✓] Found: Subfinder ($subfinder_count), Assetfinder ($assetfinder_count), Total unique ($total_workspaces)${NC}"
}

# HTTP probe function
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
    local workspace="$1"
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat "$workspace/result/httpx/httpx.txt" | waybackurls | anew "$workspace/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$workspace/result/wayback/wayback-tmp.txt" 2>/dev/null | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$workspace/result/wayback/wayback.txt"
    
    rm -f "$workspace/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$workspace/result/wayback/wayback.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $total_urls unique URLs${NC}"
}

# JavaScript file discovery
find_js_files() {
    local workspace="$1"
    echo -e "\n${BLUE}[+] Searching for JavaScript files...${NC}"
    
    # Create necessary directories
    mkdir -p "$workspace/result/js"/{valid,endpoints,secrets,analysis}
    
    # Define output files
    input_file="$workspace/result/wayback/wayback.txt"
    js_output="$workspace/result/js/valid/js_files.txt"
    min_js_output="$workspace/result/js/valid/minified_js.txt"
    custom_js_output="$workspace/result/js/valid/custom_js.txt"
    lib_js_output="$workspace/result/js/valid/library_js.txt"
    secret_file="$workspace/result/js/secrets/secrets.txt"
    endpoints_file="$workspace/result/js/endpoints/api_endpoints.txt"
    analysis_file="$workspace/result/js/analysis/js_analysis.txt"
    
    if [ ! -f "$input_file" ] || [ ! -s "$input_file" ]; then
        echo -e "${RED}[!] No input URLs found in wayback data.${NC}"
        return 1
    fi

    echo -e "${MAGENTA}[*] Extracting and validating JavaScript files...${NC}"
    
    # Extract JS files with better pattern matching
    cat "$input_file" | grep -iE '\.js($|\?|#|&|/)' | sort -u > "$js_output.tmp"
    
    # Initialize counters
    total_js=0
    valid_js=0
    minified_js=0
    custom_js=0
    library_js=0

    # Process each JS file
    while IFS= read -r url; do
        ((total_js++))
        display_progress "$total_js" "$(wc -l < "$js_output.tmp")" "Processing JS files"
        
        # Validate JS URL and content
        if curl -sL -m 10 "$url" -o "/tmp/temp.js" 2>/dev/null; then
            # Check if file is actually JavaScript
            mime_type=$(file -b --mime-type "/tmp/temp.js")
            if [[ "$mime_type" =~ "javascript" || "$mime_type" =~ "text" ]]; then
                # Analyze file content
                filesize=$(wc -c < "/tmp/temp.js")
                
                # Skip empty files
                if [ "$filesize" -lt 50 ]; then
                    continue
                fi
                
                # Check if minified
                if grep -q '^[^
]*$' "/tmp/temp.js" && [ "$filesize" -gt 5000 ]; then
                    echo "$url" >> "$min_js_output"
                    ((minified_js++))
                fi
                
                # Detect common libraries
                if grep -qiE 'jquery|angular|react|vue|bootstrap|lodash|moment|axios|d3|three.js' "/tmp/temp.js"; then
                    echo "$url" >> "$lib_js_output"
                    ((library_js++))
                else
                    echo "$url" >> "$custom_js_output"
                    ((custom_js++))
                fi
                
                # Extract potential sensitive information
                echo -e "\n[+] Analyzing: $url" >> "$analysis_file"
                grep -iE 'api[_-]key|apikey|secret|password|token|aws|firebase|config|private|credential' "/tmp/temp.js" >> "$analysis_file"
                
                echo "$url" >> "$js_output"
                ((valid_js++))
            fi
        fi
    done < "$js_output.tmp"
    
    rm -f "$js_output.tmp" "/tmp/temp.js"
    
    echo -e "\n${GREEN}[✓] JavaScript Analysis Complete:${NC}"
    echo -e "  ${CYAN}• Total JS files found: $total_js${NC}"
    echo -e "  ${CYAN}• Valid JS files: $valid_js${NC}"
    echo -e "  ${CYAN}• Minified JS: $minified_js${NC}"
    echo -e "  ${CYAN}• Custom JS: $custom_js${NC}"
    echo -e "  ${CYAN}• Library JS: $library_js${NC}"
    echo ""
    # Use custom regex patterns for endpoint discovery
    echo -e "${YELLOW}[*] Running custom endpoint detection...${NC}"
    cat "$js_output" | while read -r url; do
        curl -sL "$url" | grep -oE '"/[^"]*"|"/api/[^"]*"' >> "$endpoints_file.tmp"
    done
    
    # Clean and deduplicate endpoints
    if [ -f "$endpoints_file.tmp" ]; then
        cat "$endpoints_file.tmp" | \
            grep -oE '(https?:)?//[^"'\''`]\S+|/[a-zA-Z0-9_/-]+' | \
            sed 's/^\/\//https:\/\//g' | \
            sort -u > "$endpoints_file"
        rm "$endpoints_file.tmp"
        
        endpoint_count=$(wc -l < "$endpoints_file")
        echo -e "${GREEN}[✓] Found $endpoint_count unique endpoints${NC}"
    fi
    
    # Run security analysis
    echo -e "\n${MAGENTA}[*] Running security analysis on JS files...${NC}"
    
    if command -v trufflehog &> /dev/null; then
        cat "$js_output" | while read -r url; do
            trufflehog --regex --entropy=False "$url" >> "$secret_file"
        done
    fi
    
    # Generate summary report
    echo -e "\n${BLUE}[+] Generating analysis report...${NC}"
    {
        echo "JavaScript Analysis Report for $workspace"
        echo "======================================"
        echo "Generated on: $(date)"
        echo ""
        echo "Statistics:"
        echo "- Total JavaScript files: $total_js"
        echo "- Valid JavaScript files: $valid_js"
        echo "- Minified JavaScript files: $minified_js"
        echo "- Custom JavaScript files: $custom_js"
        echo "- Library JavaScript files: $library_js"
        echo "- Unique endpoints discovered: $endpoint_count"
        echo ""
        echo "High-Value Files:"
        echo "----------------"
        grep -l 'api\|config\|secret\|key\|token' "/tmp/temp.js" 2>/dev/null
    } > "$workspace/result/js/analysis/summary_report.txt"
    
    echo -e "${GREEN}[✓] JavaScript analysis completed successfully${NC}"
    echo -e "${YELLOW}[*] Check the results in $workspace/result/js/ directory${NC}"
}

# Send results to Telegram
send_to_telegram() {
    local workspace="$1"
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Summary message
        message="🔍 JS Files scan completed for: $workspace
📊 Summary:
• Subworkspaces found: $(wc -l < "$workspace/sources/all.txt" 2>/dev/null || echo "0")
• Live hosts: $(wc -l < "$workspace/result/httpx/httpx.txt" 2>/dev/null || echo "0")
• JavaScript files: $(wc -l < "$workspace/result/js/js_files.txt" 2>/dev/null || echo "0")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress bar
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
}

# Process single workspace
process_workspace() {
    local workspace="$1"
    echo -e "\n${CYAN}[+] Processing workspace: $workspace${NC}"
    setup_directories "$workspace"
    run_subworkspace_enum "$workspace"
    probe_http "$workspace"
    collect_wayback "$workspace"
    find_js_files "$workspace"
    send_to_telegram "$workspace"
    echo -e "${GREEN}[✓] Processing completed for $workspace${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    process_workspace "$workspace"
    echo -e "\n${GREEN}[✓] All tasks completed successfully!${NC}\n"
}

# Run the script
main