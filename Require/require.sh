#!/usr/bin/bash

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "This script must be run as root. Exiting."
  exit 1
fi

# Clear the screen
clear

# Update and upgrade system packages
apt update && apt upgrade -y

# Install necessary packages
apt install figlet rush wafw00f -y
apt install dnsx git subjack seclists massdns ffuf nikto nmap golang subfinder toilet pip npm -y
apt install zsh curl wget amass -y
snap install amass
apt install python3-pip -y

# Force pip package installations
pip install shodan --break-system-packages
pip install git+https://github.com/kiber-io/apkd --break-system-packages

# Clone fuzzing templates
git clone https://github.com/projectdiscovery/fuzzing-templates.git "$HOME/fuzzing-templates"

# Install Go tools
clear
figlet -w 100 -f small "Install All Tools"
go install github.com/Emoe/kxss@latest
go install github.com/kacakb/jsfinder@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/lukasikic/subzy@latest
go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest
go install github.com/hahwul/dalfox/v2@latest
go install github.com/OWASP/Amass/v3/...@master
go install github.com/projectdiscovery/notify/cmd/notify@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/httprobe@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/fff@latest
go install github.com/tomnomnom/anew@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/musana/mx-takeover@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/Ice3man543/SubOver@latest
go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest
go install github.com/ezekg/git-hound@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# Install MassDNS Resolvers
clear
figlet -w 100 -f small "Install MassDNS Resolvers"
cd /root
wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt && cp resolvers.txt /usr/share/seclists/
cd /root && rm -rf resolvers.txt

# Install Ghauri
clear
figlet -w 100 -f small "Install Ghauri"
INSTALL_DIR="/root/ghauri"
echo "Cloning the Ghauri repository..."
if git clone https://github.com/r0oth3x49/ghauri.git "$INSTALL_DIR"; then
    echo "Repository cloned successfully."
else
    echo "Error: Failed to clone the repository."
    exit 1
fi

cd "$INSTALL_DIR" || { echo "Error: Failed to change directory."; exit 1; }
echo "Installing Python dependencies..."
if python3 -m pip install --upgrade -r requirements.txt --break-system-packages; then
    echo "Dependencies installed successfully."
else
    echo "Error: Failed to install dependencies."
    exit 1
fi

echo "Running setup..."
if python3 setup.py install; then
    echo "Setup completed successfully."
else
    echo "Error: Setup failed."
    exit 1
fi

ghauri --help

# Install GF
clear
figlet -w 100 -f small "Install GF"
cd /root && git clone https://github.com/tomnomnom/gf.git
cd /usr/local && mkdir -p go/{src,bin}
cd /root/gf && cp *.zsh /usr/local/go/src
cd /root && git clone https://github.com/1ndianl33t/Gf-Patterns.git
go install github.com/tomnomnom/gf@latest
cp /root/go/bin/gf /usr/local/go/bin/
echo "source /usr/local/go/src/gf-completion.zsh" >> ~/.zshrc
source ~/.zshrc
cd /root && cp -r gf/examples ~/.gf
cd /root && cp Gf-Patterns/*.json ~/.gf

# Install SecretFinder
clear
figlet -w 100 -f small "Install SecretFinder"
cd /root
echo "127.0.0.1 $(hostname)" | sudo tee -a /etc/hosts
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
if [ -f SecretFinder.py ]; then
    sudo cp SecretFinder.py /usr/bin/secretfinder.py && sudo sed -i '1s/python$/python3/' /usr/bin/secretfinder.py && sudo chmod +x /usr/bin/secretfinder.py
else
    echo "secretfinder.py not found."
fi
pip install -r requirements.txt --break-system-packages
pip install jsbeautifier lxml requests requests_file --break-system-packages
shodan init Z2oDsaHG35oCrPkzMDZbl9zMsFMhGoWE
echo "SecretFinder has been installed."

# Install FindomXSS
clear
figlet -w 100 -f small "Install FindomXSS"
cd /root
git clone https://github.com/dwisiswant0/findom-xss.git --recurse-submodules
cp findom-xss/findom-xss.sh /usr/bin/findomxss
chmod +x /usr/bin/findomxss

# Copy all tools
clear
mod(){
cp /root/go/bin/* /usr/bin/
echo -e '#!/bin/bash\nbash /root/hades/hades $1' | sudo tee /usr/bin/hades > /dev/null && sudo chmod +x /usr/bin/hades
figlet -w 100 -f small "Copy All Tools!"
echo -e $MAGENTA""
}
mod

# Install apkscan
apks(){
REPO_URL="https://github.com/LucasFaudman/apkscan.git"
REPO_DIR=$(basename "$REPO_URL" .git)
git clone "$REPO_URL"
cd "$REPO_DIR" || exit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
cd ../
}
apks
