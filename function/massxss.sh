echo ""
        inputtarget(){
        clear
        figlet -w 100 -f small Mass XSS Injection
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
        gf_patt(){
        gf xss $domain/result/wayback/valid.txt | tee $domain/result/gf/xss.txt
        gf sqli $domain/result/wayback/valid.txt | tee $domain/result/gf/sql.txt
        gf ssrf $domain/result/wayback/valid.txt | tee $domain/result/gf/ssrf.txt
        gf redirect $domain/result/wayback/valid.txt | tee $domain/result/gf/redirect.txt
        gf rce $domain/result/wayback/valid.txt | tee $domain/result/gf/rce.txt
        gf idor $domain/result/wayback/valid.txt | tee $domain/result/gf/idor.txt
        gf lfi $domain/result/wayback/valid.txt | tee $domain/result/gf/lfi.txt
        gf ssti $domain/result/wayback/valid.txt | tee $domain/result/gf/ssti.txt
        gf debug_logic $domain/result/wayback/valid.txt | tee $domain/result/gf/debug_logic.txt
        gf img-traversal $domain/result/wayback/valid.txt | tee $domain/result/gf/img-traversal.txt
        gf interestingparams $domain/result/wayback/valid.txt | tee $domain/result/gf/interestingparams.txt
        gf aws-keys $domain/result/wayback/valid.txt | tee $domain/result/gf/aws.txt
        gf base64 $domain/result/wayback/valid.txt | tee $domain/result/gf/base64.txt
        gf cors $domain/result/wayback/valid.txt | tee $domain/result/gf/cors.txt
        gf http-auth $domain/result/wayback/valid.txt | tee $domain/result/gf/http-auth.txt
        gf php-errors $domain/result/wayback/valid.txt | tee $domain/result/gf/phpe.txt
        gf takeovers $domain/result/wayback/valid.txt | tee $domain/result/gf/takes.txt
        gf urls $domain/result/wayback/valid.txt | tee $domain/result/gf/urls.txt
        gf s3-buckets $domain/result/wayback/valid.txt | tee $domain/result/gf/s3.txt
        gf strings $domain/result/wayback/valid.txt | tee $domain/result/gf/strings.txt
        gf upload-fields $domain/result/wayback/valid.txt | tee $domain/result/gf/ups.txt
        gf servers $domain/result/wayback/valid.txt | tee $domain/result/gf/server.txt
        gf ip $domain/result/wayback/valid.txt | tee $domain/result/gf/ip.txt
        }
        gf_patt
        xss(){
        cat $domain/result/gf/xss.txt | grep -E '\bhttps?://\S+?=\S+' | grep -E '\.php|\.asp' | sort -u | sed 's/\(=[^&]*\)/=/g' | tee $domain/sources/urls-xss.txt | sort -u -o $domain/sources/urls-xss.txt && cat $domain/sources/urls-xss.txt | kxss > $domain/result/xss/kxss-results.txt 
        }
        xss
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