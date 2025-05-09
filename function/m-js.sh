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
        break
    done
    return 0
}

# Create directory structure
setup_directories() {
    local domain="$1"
    echo -e "\n${BLUE}[+] Setting up workspace for ${domain}...${NC}"
    mkdir -p "$domain"/{sources,result/{nuclei,wayback,httpx,exploit,js}}
    echo -e "${GREEN}[✓] Directory structure created${NC}"
}

# Subdomain enumeration
run_subdomain_enum() {
    local domain="$1"
    echo -e "\n${BLUE}[+] Starting subdomain enumeration for ${domain}...${NC}"
    
    echo -e "${MAGENTA}[*] Running Subfinder...${NC}"
    subfinder -d "$domain" -o "$domain/sources/subfinder.txt"
    subfinder_count=$(wc -l < "$domain/sources/subfinder.txt" 2>/dev/null || echo "0")
    
    echo -e "${MAGENTA}[*] Running Assetfinder...${NC}"
    assetfinder -subs-only "$domain" | tee "$domain/sources/assetfinder.txt"
    assetfinder_count=$(wc -l < "$domain/sources/assetfinder.txt" 2>/dev/null || echo "0")
    
    cat "$domain/sources/"*.txt 2>/dev/null | sort -u > "$domain/sources/all.txt"
    total_domains=$(wc -l < "$domain/sources/all.txt" 2>/dev/null || echo "0")
    
    echo -e "${GREEN}[✓] Found: Subfinder ($subfinder_count), Assetfinder ($assetfinder_count), Total unique ($total_domains)${NC}"
}

# HTTP probe function
probe_http() {
    local domain="$1"
    echo -e "\n${BLUE}[+] Probing for live hosts...${NC}"
    cat "$domain/sources/all.txt" | httprobe | tee "$domain/result/httpx/httpx.txt"
    live_hosts=$(wc -l < "$domain/result/httpx/httpx.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $live_hosts live hosts${NC}"
}

# Wayback data collection
collect_wayback() {
    local domain="$1"
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    cat "$domain/result/httpx/httpx.txt" | waybackurls | anew "$domain/result/wayback/wayback-tmp.txt"
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat "$domain/result/wayback/wayback-tmp.txt" 2>/dev/null | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > "$domain/result/wayback/wayback.txt"
    
    rm -f "$domain/result/wayback/wayback-tmp.txt"
    total_urls=$(wc -l < "$domain/result/wayback/wayback.txt" 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $total_urls unique URLs${NC}"
}

# JavaScript file discovery
find_js_files() {
    local domain="$1"
    echo -e "\n${BLUE}[+] Searching for JavaScript files...${NC}"
    
    # Create necessary directories
    mkdir -p "$domain/result/js"/{valid,endpoints,secrets,analysis}
    
    # Define output files
    input_file="$domain/result/wayback/wayback.txt"
    js_output="$domain/result/js/valid/js_files.txt"
    min_js_output="$domain/result/js/valid/minified_js.txt"
    custom_js_output="$domain/result/js/valid/custom_js.txt"
    lib_js_output="$domain/result/js/valid/library_js.txt"
    secret_file="$domain/result/js/secrets/secrets.txt"
    endpoints_file="$domain/result/js/endpoints/api_endpoints.txt"
    analysis_file="$domain/result/js/analysis/js_analysis.txt"
    
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
        echo "JavaScript Analysis Report for $domain"
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
    } > "$domain/result/js/analysis/summary_report.txt"
    
    echo -e "${GREEN}[✓] JavaScript analysis completed successfully${NC}"
    echo -e "${YELLOW}[*] Check the results in $domain/result/js/ directory${NC}"
}

# Send results to Telegram
send_to_telegram() {
    local domain="$1"
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    if [[ -f telegram_token.txt && -f telegram_chat_id.txt ]]; then
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)
        
        # Summary message
        message="🔍 JS Files scan completed for: $domain
📊 Summary:
• Subdomains found: $(wc -l < "$domain/sources/all.txt" 2>/dev/null || echo "0")
• Live hosts: $(wc -l < "$domain/result/httpx/httpx.txt" 2>/dev/null || echo "0")
• JavaScript files: $(wc -l < "$domain/result/js/js_files.txt" 2>/dev/null || echo "0")
📤 Sending detailed results..."

        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
             -d chat_id="$chat_id" \
             -d text="$message" > /dev/null 2>&1

        # Send files with progress bar
        total_files=$(find "$domain" -type f | wc -l)
        current=0
        
        find "$domain" -type f | while read -r file; do
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
    local domain="$1"
    echo -e "\n${CYAN}[+] Processing domain: $domain${NC}"
    setup_directories "$domain"
    run_subdomain_enum "$domain"
    probe_http "$domain"
    collect_wayback "$domain"
    find_js_files "$domain"
    send_to_telegram "$domain"
    echo -e "${GREEN}[✓] Processing completed for $domain${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    process_domain "$domain"
    echo -e "\n${GREEN}[✓] All tasks completed successfully!${NC}\n"
}

# Run the script
main