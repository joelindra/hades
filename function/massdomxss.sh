echo ""
        inputtarget(){
        clear
        figlet -w 100 -f small DOM XSS Exploit
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
        mkdir -p $domain $domain/sources $domain/result $domain/result/xss $domain/result/wayback $domain/result/gf $domain/result/httpx
        subfinder -d $domain -o $domain/sources/subfinder.txt
        assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
        cat $domain/sources/*.txt > $domain/sources/all.txt
        }
        domain_enum
        httpx(){
        cat $domain/sources/all.txt | httprobe | tee $domain/result/httpx/httpx.txt
        }
        httpx
        wayback(){
        cat $domain/result/httpx/httpx.txt | waybackurls | anew $domain/result/wayback/wayback-tmp.txt 
        cat $domain/result/wayback/wayback-tmp.txt | command egrep -v "\.woff|\.ttf|\.svg|\.eot|\.png|\.jpeg|\.jpg|\.png|\.css|\.ico" |  sed 's/:80//g;s/:443//g' | sort -u > $domain/result/wayback/wayback.txt
        rm $domain/result/wayback/wayback-tmp.txt
        }
        wayback
        valid_url(){
        cat "$domain/result/wayback/wayback.txt" | ffuf -c -u "FUZZ" -w - -of csv -o "$domain/result/wayback/valid-tmp.txt" -t 100 -rate 1000
        cat $domain/result/wayback/valid-tmp.txt | grep http | awk -F "," '{print $1}' >> $domain/result/wayback/valid.txt
        rm $domain/result/wayback/valid-tmp.txt
        }
        valid_url
        domxss(){
        cat $domain/result/wayback/valid.txt | findomxss | tee $domain/result/xss/domxss-results.txt
        }
        domxss
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