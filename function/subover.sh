echo ""
        inputtarget(){
        clear
        figlet -w 100 -f small Subdomain Takeovers
        echo -e $MAGENTA
        echo -n "🌐 Enter the domain you want to explore: " 
        read domain
        }
        inputtarget
        clear
        waf(){
        figlet -w 100 -f small Checking Waff
        wafw00f $domain
        }
        waf
        domain_enum(){
        mkdir -p $domain $domain/sources $domain/result $domain/result/takeover $domain/result/httpx
        subfinder -d $domain -o $domain/sources/subfinder.txt
        assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
        cat $domain/sources/*.txt > $domain/sources/all.txt
        }
        domain_enum
        httpx(){
        cat $domain/sources/all.txt | httprobe | tee $domain/result/httpx/httpx.txt
        }
        httpx
        takeoff(){
        wget -q https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json -O /root/hades/fingerprints.json
        subjack -w $domain/result/httpx/httpx.txt -t 100 -timeout 30 -ssl -c /root/hades/fingerprints.json -v 3 >> $domain/result/takeover/takeover.txt
        }
        takeoff
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