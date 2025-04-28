# HADES v4

## 🔥 Overview

HADES is a comprehensive security testing and assessment tool designed to automate and simplify various security tasks for penetration testers, security researchers, and ethical hackers. The tool provides a unified interface for reconnaissance, vulnerability scanning, and penetration testing across multiple targets.

Created by Joel Indra (Anonre), HADES combines multiple specialized tools into one powerful security testing framework.

## ✨ Features

### Reconnaissance Tools
- **Mass Reconnaissance** - Automated scanning of multiple targets
- **Single Recon** - Detailed information gathering for individual targets

### Injection Testing
- **SQL Injection Testing** (Mass & Single target)
- **Cross-Site Scripting (XSS) Scanner** (Mass & Single target)
- **Local File Inclusion (LFI) Testing**

### Assessment Tools
- **Complete Security Assessment** - Comprehensive vulnerability scanning
- **DOM XSS Vulnerability Scanner** - Detect DOM-based XSS vulnerabilities

### Special Tools
- **Subdomain Takeover Scanner** - Identify potential subdomain takeover vulnerabilities
- **Directory Enumeration Tool** - Discovery of hidden directories and files
- **JavaScript File Discovery** - Locate and analyze JavaScript files for vulnerabilities

## 🛠️ Installation

### Prerequisites
- Bash shell environment
- Internet connection for dependency installation

### Quick Installation

1. Clone the repository:
```bash
git clone https://github.com/joelindra/hades.git
cd hades
```

2. Make the script executable:
```bash
chmod +x hades
```

3. Install requirements:
```bash
./hades -i
```

## 📚 Usage

HADES can be executed using the main script with various command-line options:

```bash
./hades [options]
```

### Available Options

#### Reconnaissance Tools
- `-d, --mass-recon` - Mass Reconnaissance Scanning
- `-s, --single-recon` - Single Target Reconnaissance

#### Injection Testing
- `-p, --mass-sql-inject` - Mass SQL Injection Scanner
- `-o, --single-sql-inject` - Single SQL Injection Test
- `-w, --mass-xss` - Mass XSS Vulnerability Scanner
- `-x, --single-xss` - Single XSS Testing
- `-n, --single-lfi` - Local File Inclusion Test

#### Assessment Tools
- `-m, --mass-assessment` - Complete Security Assessment
- `-v, --mass-dom-xss` - DOM XSS Vulnerability Scanner

#### Special Tools
- `-y, --sub-takeover` - Subdomain Takeover Scanner
- `-q, --dirsearch-patrol` - Directory Enumeration Tool
- `-l, --mass-js-finder` - JavaScript File Discovery

#### System
- `-i, --install-requirements` - Install Required Dependencies
- `-h, --help` - Display Help Message

## 📋 Examples

### Basic Reconnaissance
```bash
# Run reconnaissance on a single target
./hades -s

# Run mass reconnaissance on multiple targets
./hades -d
```

### Vulnerability Testing
```bash
# Test for SQL injection vulnerabilities on multiple targets
./hades -p

# Scan for XSS vulnerabilities on a single target
./hades -x
```

### Complete Assessment
```bash
# Run a comprehensive security assessment
./hades -m
```

## 🔒 Security Note

This tool is designed for ethical hacking and security assessment purposes. Always ensure you have proper authorization before testing any target. Unauthorized testing may be illegal and unethical.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgements

![image](https://github.com/user-attachments/assets/d2e57c02-845a-4c3f-9c52-d8a6c7d42613)


Special thanks to the security community and the developers of the tools integrated within HADES.

---

Created with ❤️ by Joel Indra (Anonre)
