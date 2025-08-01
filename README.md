<div align="center">
  <img width="200" height="200" alt="awx" src="https://github.com/user-attachments/assets/a4625b85-522b-4c94-a8e8-9f418074de9b" />
</div>

**AWX** is a specialized tool designed to rapidly identify leaked AWS secrets in web applications. It's particularly valuable for bug bounty hunters and penetration testers, supporting both single targets and large-scale scanning operations.

#### fags:
```bash
-help: Display usage information
-up: Update the tool
-f <target_file.txt>: Specify file containing target URLs (base URLs only)
-u <http://example.com>: Scan a single URL
-reg <regex.yaml>: Custom regex pattern file (optional)
-t <int>: Number of threads to use
-s: Silent mode (output only AWS secrets)
```
#### usage:
```bash
# Single URL scan
python awx.py -u https://example.com
# File-based scanning
python awx.py targets.txt
python awx.py -f targets.txt
# Advanced scanning with custom settings
python awx.py -f targets.txt -s -t 50
# Custom regex pattern
python awx.py -f targets.txt -reg custom_reg.yaml
subfinder -d example.com -silent | httpx -silent | awx
```
#### installation:
Add the following alias to your `~/.bashrc` or `/.zshrc`

```
alias awx='python /path/to/awx.py'
```

Reload your shell configuration
```
source ~/.bashrc    # For bash users
source ~/.zshrc     # For zsh users
```
#### reference:

https://hackerone.com/reports/2401648
https://www.twilio.com/blog/incident-report-api-security-issue
https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
https://www.capitalone.com/facts2019/
https://sysdig.com/blog/cryptojacking-cloud/
https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#require-mfa
https://attack.mitre.org/techniques/TA0003/
https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-008a
