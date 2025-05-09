# HADESv5 - Phantom Security Initiative
## 🛡️ Overview

HADES (Advanced Security Testing & Vulnerability Assessment) is a comprehensive security testing framework designed for penetration testers, security researchers, and DevSecOps professionals. This toolkit provides a unified command-line interface for various security testing modules, enabling efficient vulnerability discovery and assessment.

Developed by Joel Indra (Anonre), HADES offers a streamlined approach to security testing with an emphasis on usability and comprehensive reporting.

## ✨ Features

HADES combines multiple security testing tools into a single framework with a user-friendly interface and comprehensive reporting capabilities:

### 🔍 Reconnaissance Tools
- **Mass Reconnaissance** - Automated discovery and information gathering for multiple targets
- **Single Target Reconnaissance** - Detailed information gathering focused on a specific target

### 💉 Injection Testing
- **SQL Injection** - Test targets for SQL injection vulnerabilities (both mass and single target)
- **Cross-Site Scripting (XSS)** - Identify XSS vulnerabilities with mass or targeted scanning
- **Local File Inclusion (LFI)** - Test for local file inclusion vulnerabilities

### 📊 Assessment Tools
- **Complete Security Assessment** - Comprehensive vulnerability scanning and assessment

### 🧰 Special Tools
- **Subdomain Takeover Scanner** - Identify vulnerable subdomains
- **Directory Enumeration** - Discover hidden directories and files
- **JavaScript File Discovery** - Find and analyze JavaScript files
- **CORS Misconfiguration Detection** - Identify Cross-Origin Resource Sharing issues
- **CSRF Vulnerability Scanner** - Detect Cross-Site Request Forgery vulnerabilities

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/joelindra/hades.git

# Navigate to the directory
cd hades

# Make the script executable
chmod +x hades

# Install required dependencies
./hades -i
```

## 📖 Usage

HADES offers a variety of command-line options for different security testing scenarios:

```bash
./hades [options]
```

### Command Options

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

#### Special Tools
- `-y, --sub-takeover` - Subdomain Takeover Scanner
- `-q, --dirsearch-patrol` - Directory Enumeration Tool
- `-l, --mass-js-finder` - JavaScript File Discovery
- `-k, --mass-cors` - Mass Auto CORS Detection
- `-u, --mass-csrf` - Mass Auto CSRF Detection

#### System Management
- `-i, --install-requirements` - Install Required Dependencies
- `-h, --help` - Display Help Message

## 🔧 Examples

```bash
# Display help
./hades --help

# Install required dependencies
./hades --install-requirements

# Run reconnaissance on a single target
./hades --single-recon

# Run a complete security assessment
./hades --mass-assessment

# Test for SQL injections on a single target
./hades --single-sql-inject

# Run directory enumeration
./hades --dirsearch-patrol
```

## ⚠️ Disclaimer

HADES is designed for legal security testing with proper authorization. Unauthorized security testing may violate laws and regulations. Always ensure you have explicit permission before testing any systems or applications.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Contact

Joel Indra (Anonre) - [GitHub Profile](https://github.com/anonre)

Project Link: [https://github.com/anonre/hades](https://github.com/anonre/hades)

---

![image](https://github.com/user-attachments/assets/0c97b804-cd86-4164-a264-8cb696a7a617)


⚡ Developed with passion by the Phantom Security Initiative
