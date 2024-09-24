        # Function to check internet connection
        clear
        figlet -w 100 -f small Prepare Install All You Need!
        check_internet() {
            echo "Checking internet connection..."
            if ping -c 1 google.com &> /dev/null; then
                echo -e "\e[32mConnected to the internet!\e[0m"  # Green for success
            else
                echo -e "\e[31mFailed to connect to the internet!\e[0m"  # Red for failure
                exit 1  # Exit if no internet connection
            fi
            sleep 2
            clear
        }

        # Function to install required dependencies based on the OS
        install_requirements() {
            echo "Checking system OS..."
            if [[ "$(uname)" == "Darwin" ]]; then
                echo -e "\e[34mRunning on macOS. Installing macOS-specific requirements...\e[0m"
                cd Require && bash require-mac.sh || { echo -e "\e[31mFailed to install macOS requirements.\e[0m"; exit 1; }
            elif [[ "$(uname)" == "Linux" ]]; then
                echo -e "\e[34mRunning on Linux. Installing Linux-specific requirements...\e[0m"
                cd Require && bash require.sh || { echo -e "\e[31mFailed to install Linux requirements.\e[0m"; exit 1; }
            else
                echo -e "\e[31mUnsupported operating system.\e[0m"
                exit 1
            fi
            sleep 2
            clear
        }

        # Main function
        main() {
            check_internet  # Check if internet is available
            install_requirements  # Install required dependencies
            echo -e "\e[32mAll checks passed and requirements installed successfully!\e[0m"
        }

        # Start script
        main
