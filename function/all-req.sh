#!/bin/bash

# ASCII Art Banner
print_banner() {
    echo -e "\e[1;36m"
    cat << "EOF"
    ╔══════════════════════════════════════════╗
    ║      System Installation Assistant       ║
    ║        All-In-One Setup Script           ║
    ╚══════════════════════════════════════════╝
EOF
    echo -e "\e[0m"
}

# Spinner animation for loading states
spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Function to check internet connection
check_internet() {
    echo -e "\n\e[1;33m📡 Checking Internet Connection...\e[0m"
    if ping -c 1 google.com &> /dev/null; then
        echo -e "\e[1;32m✔️  Connected to the internet!\e[0m"
        echo -e "\e[90m└── Connection status: \e[32mONLINE\e[0m"
    else
        echo -e "\e[1;31m❌ No Internet Connection!\e[0m"
        echo -e "\e[90m└── Connection status: \e[31mOFFLINE\e[0m"
        exit 1
    fi
    sleep 1
}

# Function to install required dependencies
install_requirements() {
    echo -e "\n\e[1;33m🔍 Detecting Operating System...\e[0m"
    
    case "$(uname)" in
        "Darwin")
            echo -e "\e[1;34m🍎 macOS Detected\e[0m"
            echo -e "\e[90m└── Installing macOS requirements...\e[0m"
            (cd require && bash require-mac.sh) || {
                echo -e "\e[1;31m❌ Installation Failed!\e[0m"
                echo -e "\e[31m└── Error: Could not install macOS requirements\e[0m"
                exit 1
            }
            ;;
        "Linux")
            echo -e "\e[1;34m🐧 Linux Detected\e[0m"
            echo -e "\e[90m└── Installing Linux requirements...\e[0m"
            (cd require && bash require.sh) || {
                echo -e "\e[1;31m❌ Installation Failed!\e[0m"
                echo -e "\e[31m└── Error: Could not install Linux requirements\e[0m"
                exit 1
            }
            ;;
        *)
            echo -e "\e[1;31m❌ Unsupported Operating System\e[0m"
            echo -e "\e[31m└── This script only supports macOS and Linux\e[0m"
            exit 1
            ;;
    esac
}

# Progress bar function
show_progress() {
    local duration=$1
    local steps=20
    local sleep_time=$(bc <<< "scale=3; $duration/$steps")
    
    echo -ne "\n\e[1;36mProgress: \e[0m"
    for ((i=0; i<$steps; i++)); do
        echo -ne "\e[1;32m▓\e[0m"
        sleep $sleep_time
    done
    echo -e "\n"
}

# Main function
main() {
    clear
    print_banner
    
    check_internet
    show_progress 2
    
    install_requirements
    show_progress 1
    
    echo -e "\n\e[1;32m✨ Installation Complete!\e[0m"
    echo -e "\e[90m└── All requirements have been successfully installed\e[0m"
}

# Start script
main