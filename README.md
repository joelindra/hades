# HADES - Elegant Security Testing Framework

**Security Testing Framework v6.0**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-6.0-green.svg)](https://github.com/joelindra/hades)
[![Bash](https://img.shields.io/badge/bash-5.0+-red.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

*An elegant, modern security testing framework with a beautiful command-line interface*

</div>

## 🌟 Features

HADES is a comprehensive security testing framework designed with elegance and efficiency in mind. It provides a beautiful command-line interface with smooth animations and color-coded output for enhanced user experience.

### 🔍 Reconnaissance
- **Mass Target Scanning** - Automated reconnaissance across multiple targets
- **Single Target Analysis** - Deep dive into individual targets
- **Port Scanning** - Comprehensive port discovery and analysis

### 💉 Injection Testing
- **SQL Injection** - Mass and single target SQL injection testing
- **XSS Vulnerabilities** - Cross-site scripting detection and exploitation
- **LFI Exploits** - Local file inclusion vulnerability testing

### 🛡️ Security Assessment
- **Full Security Assessment** - Comprehensive vulnerability analysis
- **CORS Misconfiguration** - Cross-origin resource sharing testing
- **CSRF Weakness Detection** - Cross-site request forgery analysis

### 🎯 Special Operations
- **Subdomain Takeover** - Identify and exploit subdomain vulnerabilities
- **Directory Scanning** - Intelligent directory and file discovery
- **JavaScript Secret Finder** - Extract sensitive data from JS files

## 🚀 Installation

### Prerequisites
- Linux operating system (Kali recommended)
- Bash 5.0 or higher
- Internet connection for dependency installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/joelindra/hades.git

# Navigate to directory
cd hades

# Make executable
chmod +x hades

# Install dependencies
./hades -i
```

## 📖 Usage

### Basic Commands
```bash
# Display help and all available options
./hades -h

# Install all dependencies
./hades -i
```

### Reconnaissance Operations
```bash
# Mass target reconnaissance
./hades -d

# Single target reconnaissance
./hades -s

# Port scanning
./hades -f
```

### Injection Testing
```bash
# Mass SQL injection testing
./hades -p

# Single target SQL injection
./hades -o

# Mass XSS vulnerability scanning
./hades -w

# Single XSS payload testing
./hades -x

# Local file inclusion testing
./hades -n
```

### Security Assessment
```bash
# Full security assessment
./hades -m

# CORS misconfiguration testing
./hades -k

# CSRF weakness analysis
./hades -u
```

### Special Operations
```bash
# Subdomain takeover detection
./hades -y

# Directory and file discovery
./hades -q

# JavaScript secret extraction
./hades -l
```

## 🎨 Interface Preview

HADES features a beautiful command-line interface with:
- **Elegant Color Scheme** - Soft, eye-friendly colors
- **Smooth Animations** - Progress bars and typing effects
- **Session Management** - Unique session IDs and timestamps
- **Error Handling** - Graceful error management with detailed logging

## 📋 Command Reference

| Short | Long Form | Description | Category |
|-------|-----------|-------------|----------|
| `-d` | `--mass-recon` | Mass Target Scan | Reconnaissance |
| `-s` | `--single-recon` | Single Target Scan | Reconnaissance |
| `-f` | `--port-scan` | Port Scanner | Reconnaissance |
| `-p` | `--mass-sql` | SQL Injection Scan | Injection |
| `-o` | `--single-sql` | SQL Injection Test | Injection |
| `-w` | `--mass-xss` | XSS Vulnerability | Injection |
| `-x` | `--single-xss` | XSS Payload Test | Injection |
| `-n` | `--single-lfi` | LFI Exploit | Injection |
| `-m` | `--mass-assess` | Full Assessment | Assessment |
| `-y` | `--sub-takeover` | Subdomain Takeover | Special Ops |
| `-q` | `--dir-patrol` | Directory Scanner | Special Ops |
| `-l` | `--js-finder` | JS Secret Finder | Special Ops |
| `-k` | `--mass-cors` | CORS Misconfig | Special Ops |
| `-u` | `--mass-csrf` | CSRF Weakness | Special Ops |
| `-i` | `--install` | Install Dependencies | System |
| `-h` | `--help` | Display Help | System |

## 🛠️ Project Structure

```
hades/
├── hades                   # Main executable script
├── function/              # Module directory
│   ├── m-recon.sh        # Mass reconnaissance
│   ├── s-recon.sh        # Single reconnaissance
│   ├── s-port.sh         # Port scanning
│   ├── m-sqli.sh         # Mass SQL injection
│   ├── s-sqli.sh         # Single SQL injection
│   ├── m-xss.sh          # Mass XSS testing
│   ├── s-xss.sh          # Single XSS testing
│   ├── s-lfi.sh          # LFI testing
│   ├── m-scan.sh         # Full assessment
│   ├── takeover.sh       # Subdomain takeover
│   ├── m-csrf.sh         # CSRF testing
│   ├── dir-scan.sh       # Directory scanning
│   ├── m-js.sh           # JavaScript analysis
│   ├── m-cors.sh         # CORS testing
│   └── all-req.sh        # Dependency installer
├── logs/                 # Session logs
└── README.md            # This file
```

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for educational purposes and authorized security testing only.

- Only use HADES on systems you own or have explicit permission to test
- Unauthorized access to computer systems is illegal in most jurisdictions
- The authors are not responsible for any misuse of this tool
- Always follow responsible disclosure practices
- Ensure compliance with local laws and regulations

## 🔒 Ethical Guidelines

When using HADES:
1. **Get Permission** - Always obtain written authorization before testing
2. **Document Everything** - Keep detailed logs of all testing activities
3. **Report Responsibly** - Follow responsible disclosure practices
4. **Respect Scope** - Stay within the defined testing boundaries
5. **Protect Data** - Handle any discovered vulnerabilities with care

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Guidelines
- Follow bash best practices
- Maintain the elegant UI consistency
- Add proper error handling
- Include documentation for new features
- Test thoroughly before submitting

### Reporting Issues
When reporting issues, please include:
- Operating system and version
- Bash version
- Complete error messages
- Steps to reproduce the issue

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Joel Indra - Anonre**
- GitHub: [@joelindra](https://github.com/joelindra)
- Created: 2025

## 🙏 Acknowledgments

- Thanks to all security researchers and tool developers
- Inspired by the need for elegant security testing tools
- Built with love for the cybersecurity community

## 📞 Support

If you find HADES useful, please:
- ⭐ Star this repository
- 🐛 Report bugs and issues
- 💡 Suggest new features
- 🔄 Share with the community

---

![image](https://github.com/user-attachments/assets/c8c2f079-bda2-43d0-b404-e8df689381ab)

*Remember: With great power comes great responsibility*

</div>
