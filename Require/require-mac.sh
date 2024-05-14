#!/bin/bash

# Install Homebrew if not installed
if ! command -v brew &> /dev/null; then
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Update Homebrew and install necessary packages
brew update
brew upgrade
brew install rush
brew install dnsx git massdns ffuf nikto nmap go subfinder toilet curl wget amass

# Install additional tools
brew install figlet
brew install zsh
brew install python@3
pip3 install shodan
brew install golang
brew install node
sudo snap install amass

# Clone fuzzing-templates
home_dir="$HOME"
git clone https://github.com/projectdiscovery/fuzzing-templates.git "~/fuzzing-templates"

# Install Go tools
clear
  go install -v github.com/kacakb/jsfinder@latest
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
cd /usr/local/share
sudo wget https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt
cd -

# Install GF (Grep-friendly)
clear
sudo cd ~ && git clone https://github.com/tomnomnom/gf.git
sudo mkdir -p /usr/local/go/src /usr/local/go/bin
sudo cd ~/gf && sudo cp *.zsh /usr/local/go/src
sudo cd ~ && git clone https://github.com/1ndianl33t/Gf-Patterns.git
sudo go install github.com/tomnomnom/gf@latest
sudo cp ~/go/bin/gf /usr/local/go/bin/
sudo echo "source /usr/local/go/src/gf-completion.zsh" >> ~/.zshrc
source .zshrc
sudo cp -r ~/gf/examples ~/.gf
sudo cp ~/Gf-Patterns/*.json ~/.gf

# Install Ghauri
clear
cd ~ && git clone https://github.com/r0oth3x49/ghauri.git
cd ghauri
pip3 install --upgrade -r requirements.txt
python3 setup.py install
ghauri --help

# Install Wafw00f
cd ~ && git https://github.com/EnableSecurity/wafw00f.git
cd wafw00f
python3 setup.py install
cd ~ && wafw00f --version

# Install SecretFinder
clear
echo "127.0.0.1 $(hostname)" | sudo tee -a /etc/hosts
git clone https://github.com/m4ll0k/SecretFinder.git secretfinder
cd secretfinder
if [ -f SecretFinder.py ]; then
    sudo cp SecretFinder.py /usr/local/bin/secretfinder.py && sudo sed -i '' '1s/python$/python3/' /usr/local/bin/secretfinder.py && sudo chmod +x /usr/local/bin/secretfinder.py
else
    echo "SecretFinder.py not found."
fi
pip3 install -r requirements.txt
pip3 install jsbeautifier lxml requests requests_file
shodan init Z2oDsaHG35oCrPkzMDZbl9zMsFMhGoWE
echo "SecretFinder has been installed."

# Copy Go tools to /usr/bin/
cp ~/go/bin/* /usr/local/bin/

# Create Hades script
echo -e '#!/bin/bash\nbash ~/H4D3S/hades $1' | sudo tee /usr/local/bin/hades > /dev/null && sudo chmod +x /usr/local/bin/hades

# Display message
clear
echo -e "Tools installed successfully!\n"
