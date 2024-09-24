echo ""
        inputtarget(){
        clear
        figlet -w 100 -f small APK Enumeration
        echo -e $MAGENTA
        echo -n "🌐 Enter the apk you want to explore: " 
        read apk
        }
        inputtarget
        clear
        apks(){
        apkscan "$apk" -o "$apk/results/${apk}_file.yaml"
        }
        apks
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