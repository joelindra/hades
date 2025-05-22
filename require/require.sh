#!/usr/bin/bash

# Colors and formatting
RED='\e[1;31m'
GREEN='\e[1;32m'
YELLOW='\e[1;33m'
BLUE='\e[1;34m'
MAGENTA='\e[1;35m'
CYAN='\e[1;36m'
NC='\e[0m' # No Color

# ASCII Art Banner
print_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════╗
    ║        🛠️  Security Tools Installer 🛡️       ║
    ║        Advanced Penetration Testing Kit       ║
    ╚═══════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Progress indicator
show_progress() {
    local message="$1"
    echo -ne "\n${YELLOW}⚡ ${message}${NC}"
    for i in {1..3}; do
        echo -ne "."
        sleep 0.5
    done
    echo -e "\n"
}

# Success message
success_msg() {
    echo -e "${GREEN}✔️ $1${NC}"
}

# Error message
error_msg() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check root privileges
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error_msg "This script must be run as root"
    fi
    success_msg " Root privileges verified"
}

# System update function
update_system() {
    show_progress "Updating system packages"
    if apt update && apt upgrade -y; then
        success_msg " System updated successfully"
    else
        error_msg "Failed to update system"
    fi
}

# Install base packages
install_base_packages() {
    echo -e "\n${CYAN}📦 Installing Base Packages${NC}"
    packages=(
        "figlet" "rush" "wafw00f" "dnsx" "git" "subjack" "seclists" 
        "massdns" "ffuf" "nikto" "nmap" "golang" "subfinder" "toilet" 
        "pip" "npm" "zsh" "curl" "wget" "amass" "python3-pip" "bc" "dos2unix"
    )
    
    for package in "${packages[@]}"; do
        echo -ne "${YELLOW}Installing ${package}...${NC}"
        if apt install -y "$package" &>/dev/null; then
            echo -e "${GREEN} ✓${NC}"
        else
            echo -e "${RED} ✗${NC}"
        fi
    done
}

# Install pip packages
install_pip_packages() {
    echo -e "\n${CYAN}📦 Installing Pip Packages${NC}"
    show_progress "Installing Shodan"
    pip install shodan --break-system-packages
}

# Install Go tools
install_go_tools() {
    echo -e "\n${CYAN}🔧 Installing Go Tools${NC}"
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
        echo -ne "${YELLOW}Installing ${tool##*/}...${NC}"
        if go install "$tool" &>/dev/null; then
            echo -e "${GREEN} ✓${NC}"
        else
            echo -e "${RED} ✗${NC}"
        fi
    done
}

# Install MassDNS Resolvers
install_massdns_resolvers() {
    show_progress "Installing MassDNS Resolvers"
    cd /root || exit
    if wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt; then
        cp resolvers.txt /usr/share/seclists/
        rm -rf resolvers.txt
        success_msg "MassDNS Resolvers installed successfully"
    else
        error_msg "Failed to install MassDNS Resolvers"
    fi
}

# Install GF
install_gf() {
    show_progress "Installing GF"
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
    success_msg "GF installed successfully"
}

# Install SecretFinder
install_secretfinder() {
    show_progress "Installing SecretFinder"
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
        success_msg "SecretFinder installed successfully"
    else
        error_msg "SecretFinder.py not found"
    fi
}

# Copy tools to system path
copy_tools() {
    show_progress "Copying tools to system path"
    cp /root/go/bin/* /usr/bin/
    # Check if hades directory exists before attempting to create symlink
    if [ -d "/root/hades" ] && [ -f "/root/hades/hades" ]; then
        echo -e '#!/bin/bash\nbash /root/hades/hades $1' | sudo tee /usr/bin/hades > /dev/null
        chmod +x /usr/bin/hades
        success_msg "All tools copied successfully"
    else
        echo -e "${YELLOW}Warning: hades directory not found, skipping symlink creation${NC}"
        success_msg "Go tools copied successfully"
    fi
}

dos2unix ../function/dirsearchpatrol.sh
dos2unix ../function/masssqlinject.sh

# Main function
main() {
    clear
    print_banner
    
    check_root
    update_system
    install_base_packages
    install_pip_packages
    install_go_tools
    install_massdns_resolvers
    install_gf
    install_secretfinder
    copy_tools
    
    echo -e "\n${GREEN}🎉 Installation Complete!${NC}"
    echo -e "${CYAN}All security tools have been successfully installed.${NC}"
    echo -e "${YELLOW}Please restart your terminal to apply all changes.${NC}"
}

# Start script execution
main
