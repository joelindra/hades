#!/bin/bash

# Function to check internet connection
check_internet() {
    echo "Checking Internet Connection..."
    if ping -c 1 google.com &> /dev/null; then
        echo "Internet connection: ONLINE."
    else
        echo "Internet connection: OFFLINE. Please check your connection."
        exit 1
    fi
}

# Function to install required dependencies
install_requirements() {
    echo "Detecting Operating System..."

    case "$(uname)" in
        "Darwin")
            echo "macOS Detected. Installing macOS requirements..."
            # Assuming 'require/require-mac.sh' exists and is executable
            (cd require && bash require-mac.sh) || {
                echo "Error: Could not install macOS requirements."
                exit 1
            }
            ;;
        "Linux")
            echo "Linux Detected. Installing Linux requirements..."
            # Assuming 'require/require.sh' exists and is executable
            (cd require && bash require.sh) || {
                echo "Error: Could not install Linux requirements."
                exit 1
            }
            ;;
        *)
            echo "Unsupported Operating System. This script only supports macOS and Linux."
            exit 1
            ;;
    esac
}

# Check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo "Error: This script must be run as root."
        exit 1
    fi
    figlet Root Privileges Verified...
    echo ""
}

# System update function
update_system() {
    echo "Updating system packages..."
    echo ""
    if apt update && apt upgrade -y; then
        echo "System updated successfully."
    else
        echo "Error: Failed to update system."
        exit 1
    fi
}

# Install base packages
install_base_packages() {
    echo "Installing Base Packages..."
    echo ""
    packages=(
        "figlet" "rush" "wafw00f" "dnsx" "git" "subjack" "seclists"
        "massdns" "ffuf" "nikto" "nmap" "golang" "subfinder" "toilet"
        "pip" "npm" "zsh" "curl" "wget" "amass" "python3-pip" "bc" "dos2unix"
    )

    for package in "${packages[@]}"; do
        echo -n "Installing ${package}... "
        if apt install -y "$package" &>/dev/null; then
            echo "Done."
        else
            echo "Failed."
        fi
    done
}

# Install pip packages
install_pip_packages() {
    echo "Installing Pip Packages..."
    echo "Installing Shodan..."
    echo ""
    pip install shodan --break-system-packages
}

# Install Go tools
install_go_tools() {
    echo "Installing Go Tools..."
    echo ""
    go_tools=(
        "github.com/Emoe/kxss@latest"
        "github.com/kacakb/jsfinder@latest"
        "github.com/tomnomnom/unfurl@latest"
        "github.com/hahwul/dalfox/v2@latest"
        "github.com/tomnomnom/qsreplace@latest"
        "github.com/hakluke/hakrawler@latest"
        "github.com/tomnomnom/httprobe@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/fff@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/musana/mx-takeover@latest"
        "github.com/Ice3man543/SubOver@latest"
        "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest"
        "github.com/ezekg/git-hound@latest"

        # All ProjectDiscovery tools
        "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
        "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
        "github.com/projectdiscovery/proxify/cmd/proxify@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
        "github.com/projectdiscovery/notify/cmd/notify@latest"
        "github.com/projectdiscovery/uncover/cmd/uncover@latest"
        "github.com/projectdiscovery/alterx/cmd/alterx@latest"
        "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"
        "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
        "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"
        "github.com/projectdiscovery/cloudlist/cmd/cloudlist@latest"
        "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"
        "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"
        "github.com/projectdiscovery/simplehttpserver/cmd/simplehttpserver@latest"
        "github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
        "github.com/KathanP19/Gxss@latest"
        "github.com/c1phy/sqltimer/cmd/sqltimer@latest"
    )

    for tool in "${go_tools[@]}"; do
        echo -n "Installing ${tool##*/}... "
        if go install "$tool" &>/dev/null; then
            echo "Done."
        else
            echo "Failed."
        fi
    done
}

# Install MassDNS Resolvers
install_massdns_resolvers() {
    echo "Installing MassDNS Resolvers..."
    echo ""
    cd /root || exit
    if wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt; then
        cp resolvers.txt /usr/share/seclists/
        rm -rf resolvers.txt
        echo "MassDNS Resolvers installed successfully."
    else
        echo "Error: Failed to install MassDNS Resolvers."
        exit 1
    fi
}

# Install GF
install_gf() {
    echo "Installing GF..."
    echo ""
    cd /root || exit
    git clone https://github.com/tomnomnom/gf.git
    mkdir -p /usr/local/go/{src,bin}
    cd gf && cp *.zsh /usr/local/go/src
    cd /root && git clone https://github.com/1ndianl33t/Gf-Patterns.git
    go install github.com/tomnomnom/gf@latest
    cp /root/go/bin/gf /usr/local/go/bin/
    echo "source /usr/local/go/src/gf-completion.zsh" >> ~/.zshrc
    source ~/.zshrc
    mkdir -p ~/.gf
    cp -r gf/examples ~/.gf
    cp Gf-Patterns/*.json ~/.gf
    echo "GF installed successfully."
}

# Install SecretFinder
install_secretfinder() {
    echo "Installing SecretFinder..."
    echo ""
    cd /root || exit
    echo "127.0.0.1 $(hostname)" | sudo tee -a /etc/hosts
    git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
    cd secretfinder || exit

    if [ -f SecretFinder.py ]; then
        sudo cp SecretFinder.py /usr/bin/secretfinder.py
        sudo sed -i '1s/python$/python3/' /usr/bin/secretfinder.py
        sudo chmod +x /usr/bin/secretfinder.py
        pip install -r requirements.txt --break-system-packages
        pip install jsbeautifier lxml requests requests_file --break-system-packages
        pip install jsbeautifier --break-system-packages
        shodan init Z2oDsaHG35oCrPkzMDZbl9zMsFMhGoWE
        echo "SecretFinder installed successfully."
    else
        echo "Error: SecretFinder.py not found."
        exit 1
    fi
}

# Copy tools to system path
copy_tools() {
    echo "Copying tools to system path..."
    echo ""
    cp /root/go/bin/* /usr/bin/
    # Check if hades directory exists before attempting to create symlink
    if [ -d "/root/hades" ] && [ -f "/root/hades/hades" ]; then
        echo '#!/bin/bash' | sudo tee /usr/bin/hades > /dev/null
        echo 'bash /root/hades/hades $1' | sudo tee -a /usr/bin/hades > /dev/null
        chmod +x /usr/bin/hades
        echo "All tools copied successfully."
    else
        echo "Warning: hades directory not found, skipping symlink creation."
        echo "Go tools copied successfully."
    fi
}

# Main function
main() {
    clear
    check_root
    update_system
    install_base_packages
    install_pip_packages
    install_go_tools
    install_massdns_resolvers
    install_gf
    install_secretfinder
    copy_tools

    dos2unix ../function/dirsearchpatrol.sh
    dos2unix ../function/masssqlinject.sh

    echo "Installation Complete!"
}

# Start script execution
main
