# Hades

Hades is a versatile penetration testing tool designed to simplify reconnaissance and vulnerability scanning tasks. With Hades, you can conduct targeted scans, find security loopholes, and assess the overall security posture of your applications and networks.

## Features

- **Single Recon**: Conduct targeted reconnaissance on individual targets.
- **Mass Recon**: Scale up your reconnaissance efforts for multiple targets simultaneously.
- **Single JS Finder**: Identify JavaScript files associated with a single target.
- **Mass JS Finder**: Discover JavaScript files across multiple targets efficiently.
- **Single SQL Injection**: Test for SQL injection vulnerabilities on a single target.
- **Mass SQL Injection**: Perform SQL injection tests across multiple targets at once.
- **Single XSS Injection**: Probe for cross-site scripting vulnerabilities on a single target.
- **Mass XSS Injection**: Scale up cross-site scripting tests for multiple targets.
- **Single LFI Injection**: Assess single targets for local file inclusion vulnerabilities.
- **Mass Assessment**: Conduct a comprehensive security assessment across multiple targets.
- **Subdomain Takeover**: Detect potential subdomain takeover vulnerabilities.
- **Requirements Installation**: Easily install the necessary dependencies.
- **APK Enumeration**: Easily enumeration using automate apkscan.

## Usage

Simply execute the Hades script with the desired options to utilize its functionalities. Refer to the provided options to tailor your penetration testing tasks according to your requirements.

## Getting Started

To get started with Hades, clone this repository and execute the script on your local environment. Ensure that you have the necessary dependencies installed, which can be done effortlessly using the provided installation option.

## Disclaimer

Hades is intended for ethical hacking and security testing purposes only. Ensure that you have proper authorization before using it against any system or network.

## Image Example Running Script

![image](https://github.com/user-attachments/assets/14e64d1f-2cd2-443c-90a3-af4a6fa52c07)


# Tool Required On Hades

1. figlet
2. rush
3. wafw00f
4. dnsx
5. git
6. subjack
7. seclists
8. massdns
9. ffuf
10. nikto
11. nmap
12. golang
13. subfinder
14. toilet
15. pip
16. npm
17. zsh
18. curl
19. wget
20. amass
21. shodan
22. apkd
23. fuzzing-templates
24. kxss
25. jsfinder
26. unfurl
27. subzy
28. shuffledns
29. dalfox
30. Amass
31. notify
32. qsreplace
33. hakrawler
34. nuclei
35. httpx
36. httprobe
37. waybackurls
38. assetfinder
39. fff
40. anew
41. interactsh-client
42. gau
43. mx-takeover
44. katana
45. SubOver
46. crlfuzz
47. git-hound
48. dnsx
49. massdns resolvers
50. gf
51. Gf-Patterns
52. ghauri
53. SecretFinder
54. apkscan

## New Feature: Send Results to Telegram
1. The newly added send_to_telegram function in Hades allows users to automatically send scan results directly to a specified Telegram chat. This feature works as follows:
2. Load Telegram Token and Chat ID: The function loads the Telegram bot token and chat ID from telegram_token.txt and telegram_chat_id.txt files, ensuring that the credentials are kept separate and secure.
3. Send Start Notification: A message is sent to the Telegram chat indicating that the scan has been completed for a specific domain and that the results are being sent.
4. File Transmission: The function iterates through all files within the specified domain directory and sends each one to the Telegram chat as a document.
5. Completion Notification: After all files have been sent, a final message is sent to the Telegram chat, confirming that the process is complete.
