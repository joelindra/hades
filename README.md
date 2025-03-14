# Hades - Recon & Exploitation Toolkit

Hades is a powerful penetration testing tool designed to automate common reconnaissance and exploitation tasks. It offers multiple options to perform various security tests on websites and web applications. Whether you're performing single reconnaissance, mass scanning, or exploitation (SQLi, XSS, LFI), Hades has got you covered.

## Features

- **Single Recon**: Perform basic reconnaissance on a single target.
- **Mass Recon**: Perform reconnaissance across multiple targets simultaneously.
- **Mass JS Finder**: Discover JavaScript files in bulk.
- **Single SQL Injection**: Test for SQL injection vulnerabilities on a single target.
- **Mass SQL Injection**: Perform SQL injection checks on multiple targets.
- **Single XSS**: Test for Cross-Site Scripting (XSS) vulnerabilities on a single target.
- **Mass XSS**: Perform XSS tests on multiple targets.
- **Single LFI**: Test for Local File Inclusion vulnerabilities on a single target.
- **Mass Assessment**: Perform a mass security assessment across multiple targets.
- **Subdomain Takeover**: Check for subdomain takeover vulnerabilities.
- **Dirsearch Patrol**: Run Dirsearch to find hidden directories on a target website.
- **APK Enumeration**: Enumerate APK files to find potential vulnerabilities.
- **Mass DOM XSS Exploit**: Test for DOM-based XSS vulnerabilities across multiple targets.
- **Install Requirements**: Automatically installs the necessary dependencies for the tool.
- **Help**: Display this help message.

## Usage

To use the tool, run the script with the desired options:
./hades [options]


### Available Options:
- `-s`, `--single-recon` : Single Recon
- `-d`, `--mass-recon` : Mass Recon
- `-l`, `--mass-js-finder` : Mass JS Finder
- `-o`, `--single-sql-inject` : Single SQL Injection
- `-p`, `--mass-sql-inject` : Mass SQL Injection
- `-x`, `--single-xss` : Single XSS Injection
- `-w`, `--mass-xss` : Mass XSS Injection
- `-n`, `--single-lfi` : Single LFI Injection
- `-m`, `--mass-assessment` : Mass Assessment
- `-y`, `--sub-takeover` : Subdomain Takeover
- `-q`, `--dirsearch-patrol` : Dirsearch Patrol
- `-k`, `--apk-enum` : APK Enumeration
- `-v`, `--mass-dom-xss` : Mass DOM XSS Exploit
- `-i`, `--install-requirements` : Install Requirements
- `-h`, `--help` : Display Help Message

## Installation

Ensure you have `bash` and the required dependencies installed on your system before running the script.

To install the required dependencies, run:


### Required Tools
Before running Hades, the following tools should be installed on your system:

- `figlet`
- `rush`
- `wafw00f`
- `dnsx`
- `git`
- `subjack`
- `seclists`
- `massdns`
- `ffuf`
- `nikto`
- `nmap`
- `golang`
- `subfinder`
- `toilet`
- `pip`
- `npm`
- `zsh`
- `curl`
- `wget`
- `amass`
- `shodan`
- `apkd`
- `fuzzing-templates`
- `kxss`
- `jsfinder`
- `unfurl`
- `subzy`
- `shuffledns`
- `dalfox`
- `Amass`
- `notify`
- `qsreplace`
- `hakrawler`
- `nuclei`
- `httpx`
- `httprobe`
- `waybackurls`
- `assetfinder`
- `fff`
- `anew`
- `interactsh-client`
- `gau`
- `mx-takeover`
- `katana`
- `SubOver`
- `crlfuzz`
- `git-hound`
- `massdns resolvers`
- `gf`
- `Gf-Patterns`
- `ghauri`
- `SecretFinder`
- `apkscan`

Make sure to install these tools using the appropriate installation method for your platform (e.g., `apt`, `brew`, `go get`, `pip install`, `npm install`, etc.).

## Credits

Created by **Joelindra**  
LinkedIn: [joelindra](https://www.linkedin.com/in/joelindra)

## License

This tool is open-source and released under the [MIT License](LICENSE).
