# HADES - Security Framework From HELL v7

*An elegant and comprehensive security testing toolkit for penetration testers and bug bounty hunters*

[![Version](https://img.shields.io/badge/version-7.0-blue.svg)](https://github.com/joelindra/hades)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Bash](https://img.shields.io/badge/bash-5.0+-red.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

</div>

---

## 🎯 Overview

HADES is a modern, elegant security testing framework designed for penetration testers and bug bounty hunters. It provides a comprehensive suite of automated tools for reconnaissance, vulnerability assessment, and exploitation testing with a beautiful, color-coded interface.

### ✨ Key Features

- **🎨 Elegant Interface**: Beautiful color-coded output with modern styling
- **🔍 Comprehensive Reconnaissance**: Mass and single target scanning capabilities
- **💉 Injection Testing**: SQL injection, XSS, and LFI vulnerability detection
- **🛡️ OWASP WASTG Compliance**: Following modern security testing standards
- **⚡ Automated Workflows**: Streamlined testing processes
- **📊 Session Management**: Unique session tracking and reporting

---

## 🚀 Quick Start

### Prerequisites

- Kali Linux operating system
- Root privileges (required for most operations)
- Bash 5.0 or higher

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/joelindra/hades.git
   cd hades
   ```

2. **Make the script executable**
   ```bash
   chmod +x hades.sh
   ```

3. **Install dependencies**
   ```bash
   ./hades.sh -i
   # or
   ./hades.sh --install
   ```

4. **Run with root privileges**
   ```bash
   sudo ./hades.sh
   ```

---

## 📋 Usage

### Basic Commands

```bash
# Display help and available commands
./hades.sh -h
./hades.sh --help

# Install all required dependencies
./hades.sh -i
./hades.sh --install
```

### 🔍 Reconnaissance

| Command | Description |
|---------|-------------|
| `-d, --mass-recon` | Mass target reconnaissance scan |
| `-s, --single-recon` | Single target reconnaissance |
| `-f, --port-scan` | Single port scanning |

**Examples:**
```bash
# Mass reconnaissance
./hades.sh -d

# Single target recon
./hades.sh -s

# Port scanning
./hades.sh -f
```

### 💉 Injection Testing

| Command | Description |
|---------|-------------|
| `-p, --mass-sql` | Mass SQL injection scanning |
| `-o, --single-sql` | Single target SQL injection test |
| `-w, --mass-xss` | Mass XSS vulnerability scanning |
| `-x, --single-xss` | Single XSS payload testing |
| `-n, --single-lfi` | Local File Inclusion exploit testing |

**Examples:**
```bash
# SQL injection testing
./hades.sh -p  # Mass scan
./hades.sh -o  # Single target

# XSS testing
./hades.sh -w  # Mass scan
./hades.sh -x  # Single target

# LFI testing
./hades.sh -n # Single target
```

### 🛡️ Special Operations

| Command | Description |
|---------|-------------|
| `-m, --mass-assess` | Full security assessment |
| `-y, --sub-takeover` | Subdomain takeover detection |
| `-q, --dir-patrol` | Directory and file discovery |
| `-l, --js-finder` | JavaScript secrets and API key finder |
| `-k, --mass-cors` | CORS misconfiguration detection |
| `-u, --mass-csrf` | CSRF weakness assessment |

**Examples:**
```bash
# Full assessment
./hades.sh -m

# Subdomain takeover
./hades.sh -y

# Directory scanning
./hades.sh -q

# JavaScript analysis
./hades.sh -l
```

### 🧪 OWASP WASTG Testing

| Command | Description |
|---------|-------------|
| `-e, --client-test` | Client-side security testing |
| `-b, --weak-test` | Weak cryptography detection |
| `-r, --info-test` | Information gathering (upcoming) |

**Examples:**
```bash
# Client-side testing
./hades.sh -e

# Cryptography testing
./hades.sh -b
```

---

## 🏗️ Project Structure

```
hades/
├── hades.sh           # Main executable script
├── function/               # Module directory
│   ├── m-recon.sh         # Mass reconnaissance
│   ├── s-recon.sh         # Single reconnaissance  
│   ├── s-port.sh          # Port scanning
│   ├── m-sqli.sh          # Mass SQL injection
│   ├── s-sqli.sh          # Single SQL injection
│   ├── m-xss.sh           # Mass XSS testing
│   ├── s-xss.sh           # Single XSS testing
│   ├── s-lfi.sh           # LFI testing
│   ├── m-scan.sh          # Mass assessment
│   ├── takeover.sh        # Subdomain takeover
│   ├── m-csrf.sh          # CSRF testing
│   ├── dir-scan.sh        # Directory scanning
│   ├── m-js.sh            # JavaScript analysis
│   ├── m-cors.sh          # CORS testing
│   ├── weak.sh            # Cryptography testing
│   ├── client.sh          # Client-side testing
│   └── all-req.sh         # Dependencies installer
├── README.md              # This file
└── LICENSE                # License file
```

---

## 🎨 Interface Features

HADES features a modern, elegant interface with:

- **Color-coded output** for different types of information
- **Session tracking** with unique session IDs
- **Real-time progress indicators** with elegant loading animations
- **System information display** including kernel, machine type, and timestamps
- **Error handling** with clear, formatted error messages

### Color Scheme

- 🔵 **Primary**: Soft blue for main interface elements
- 🌸 **Accent**: Soft pink for highlights and prompts
- 🟢 **Success**: Soft green for successful operations
- 🟡 **Warning**: Soft yellow for warnings and important info
- 🔴 **Danger**: Soft red for errors and critical issues
- 🟣 **Muted**: Faded purple for secondary information

---

## ⚠️ Important Notes

### Security Considerations

- **Root Access Required**: Most operations require root privileges for proper functionality
- **Educational Purpose**: This tool is designed for authorized penetration testing and educational purposes only
- **Legal Compliance**: Ensure you have proper authorization before testing any targets
- **Ethical Usage**: Always follow responsible disclosure practices

### System Requirements

- **Operating System**: Linux (Ubuntu, Debian, Kali, etc.)
- **Memory**: Minimum 1GB RAM recommended
- **Storage**: At least 500MB free space for dependencies
- **Network**: Internet connection required for some modules

---

## 🤝 Contributing

We welcome contributions to HADES! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-module`
3. **Make your changes** and test thoroughly
4. **Commit your changes**: `git commit -m 'Add new security module'`
5. **Push to the branch**: `git push origin feature/new-module`
6. **Submit a pull request**

### Development Guidelines

- Follow the existing code style and color scheme
- Add appropriate error handling
- Include documentation for new features
- Test all functionality before submitting

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

**Joel Indra (Anonre)**
- GitHub: [@joelindra](https://github.com/joelindra)
- Repository: [HADES Framework](https://github.com/joelindra/hades)

---

## 🙏 Acknowledgments

- Thanks to the security community for continuous feedback and improvements
- Special recognition to all contributors and testers
- Inspired by modern penetration testing methodologies and OWASP guidelines

---

**⚡ Happy Bug Hunting! ⚡**
