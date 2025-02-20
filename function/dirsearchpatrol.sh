#!/bin/bash
echo ""
        inputtarget(){
            clear
            figlet -w 100 -f small "Dirsearch Patrol"
            echo -n "🌐 Enter the domain you want to explore: " 
            read domain
        }
        inputtarget
        waf(){
            clear
            figlet -w 100 -f small "Checking WAF"
            wafw00f "$domain"
        }
        waf
        domain_enum(){
            mkdir -p "$domain" "$domain/sources" "$domain/result" "$domain/result/takeover" "$domain/result/httpx" "$domain/reports"
            subfinder -d "$domain" -o "$domain/sources/subfinder.txt"
            assetfinder -subs-only "$domain" | tee "$domain/sources/assetfinder.txt"
            cat "$domain/sources/"*.txt > "$domain/sources/all.txt"
        }
        domain_enum
        patrol(){
            cat "$domain/sources/all.txt" | while IFS= read -r target; do
                echo "Running Dirsearch For: $target"
                dirsearch -u "$target" -t 150 -x 403,404,401,500,429 -i 200,302,301 --random-agent -o "$domain/reports/${target//\//_}_dirsearch_report.txt"
            done
        }
        patrol
                send_to_telegram(){
        # Load Telegram token and chat ID from files
        token=$(cat telegram_token.txt)
        chat_id=$(cat telegram_chat_id.txt)

        # Message indicating the start of sending files
        message="Scan completed for domain: $domain. Sending all results from $domain/..."
        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" -d chat_id="$chat_id" -d text="$message" > /dev/null 2>&1

        # Send each file in all directories under $domain
        find "$domain" -type f | while read file; do
            curl -s -F chat_id="$chat_id" -F document=@"$file" "https://api.telegram.org/bot$token/sendDocument" > /dev/null 2>&1
        done

        # Final message indicating completion
        final_message="All files from $domain/ have been sent."
        curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" -d chat_id="$chat_id" -d text="$final_message" > /dev/null 2>&1
        }
        send_to_telegram
