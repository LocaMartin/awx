import re
import math
import yaml
import os
import argparse
import requests
import concurrent.futures
import sys
from functools import partial
from urllib.parse import urlparse
# import pkg_resources

# Color codes for terminal output
COLORS = {
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[94m',
    'RESET': '\033[0m',
}

'''
def load_regex_patterns():
    regex_path = pkg_resources.resource_filename('awx', 'regex.yaml')
'''

# Default regex file path (same directory as script)
DEFAULT_REGEX_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'regex.yaml')

def colorize(text, color):
    """Add ANSI color codes to text"""
    return f"{COLORS[color]}{text}{COLORS['RESET']}"

def load_regex_patterns(regex_file):
    """Load regex patterns from YAML file"""
    try:
        with open(regex_file, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(colorize(f"Error loading regex patterns from {regex_file}: {str(e)}", 'RED'))
        exit(1)

def calculate_entropy(data):
    """Calculate Shannon entropy for string"""
    if not data:
        return 0
    entropy = 0
    for x in (ord(c) for c in set(data)):
        p_x = float(data.count(chr(x)))/len(data)
        entropy += - p_x * math.log(p_x, 2)
    return entropy

def is_high_entropy(s):
    """Check if string has high entropy characteristic of secrets"""
    return calculate_entropy(s) > 4.5 and len(s) >= 12

def is_aws_host(response):
    """Check if the target is using AWS infrastructure"""
    aws_indicators = [
        ('Server', r'AmazonS3|CloudFront'),
        ('X-Amz-Cf-Id', r'.+'),
        ('X-Amz-Request-Id', r'.+'),
        ('Via', r'.*CloudFront.*'),
        (None, r'arn:aws:[a-z]+:[a-z0-9-]+:\d+:'),
        (None, r's3\.amazonaws\.com'),
        (None, r'cloudfront\.net'),
    ]

    for header, pattern in aws_indicators:
        if header:
            value = response.headers.get(header, '')
            if re.search(pattern, value, re.IGNORECASE):
                return True

    if any(x in response.url for x in ['amazonaws.com', 'cloudfront.net']):
        return True

    content = response.text
    for _, pattern in aws_indicators[4:]:
        if re.search(pattern, content, re.IGNORECASE):
            return True

    return False

def scan_content(content, url, aws_patterns, common_secrets):
    findings = []
    
    # AWS patterns
    for key, pattern in aws_patterns.items():
        for match in re.finditer(pattern, content, re.MULTILINE):
            findings.append({
                'type': colorize(key, 'YELLOW'),
                'match': colorize(match.group(), 'RED'),
                'context': get_context(content, match.start(), match.end()),
                'source': colorize(url, 'BLUE')
            })
    
    # Common secrets
    for line in content.split('\n'):
        for key, pattern in common_secrets.items():
            for match in re.finditer(pattern, line):
                value = match.group(3) if key == 'API_KEY' else match.group(1)
                if is_high_entropy(value):
                    findings.append({
                        'type': colorize(key, 'YELLOW'),
                        'match': colorize(value, 'RED'),
                        'context': line.strip(),
                        'source': colorize(url, 'BLUE')
                    })
    
    return findings

def get_context(content, start, end, padding=50):
    start = max(0, start - padding)
    end = min(len(content), end + padding)
    return content[start:end]

def scan_target(url, silent=False, aws_patterns=None, common_secrets=None):
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True
        )
        
        if not is_aws_host(response):
            if not silent:
                print(colorize(f"[!] {url} - Not using AWS infrastructure", 'RED'))
            return []
            
        print(colorize(f"[+] {url} - AWS infrastructure detected", 'GREEN'))
        return scan_content(response.text, url, aws_patterns, common_secrets)
        
    except Exception as e:
        if not silent:
            print(colorize(f"[!] Error scanning {url}: {str(e)}", 'RED'))
        return []

def main():
    parser = argparse.ArgumentParser(description='AWS Secret Scanner')
    parser.add_argument('-s', '--silent', action='store_true', 
                      help='Silent mode - suppress non-AWS infrastructure messages')
    parser.add_argument('-t', '--threads', type=int, default=1,
                      help='Number of threads to use')
    parser.add_argument('-c', '--processes', type=int, default=1,
                      help='Number of concurrent processes to use')
    parser.add_argument('-reg', '--regex', dest='regex_file', default=DEFAULT_REGEX_FILE,
                      help='Custom regex pattern file (optional)')
    parser.add_argument('input_file', nargs='?', help='File containing URLs to scan (positional)')
    parser.add_argument('-f', '--file', dest='input_file', help='File containing URLs to scan')
    parser.add_argument('-u', '--url', help='Scan a single URL')
    
    args = parser.parse_args()
    
    # Load regex patterns
    try:
        regex_config = load_regex_patterns(args.regex_file)
    except FileNotFoundError:
        print(colorize(f"Error: Regex file not found at {args.regex_file}", 'RED'))
        print(colorize("Please ensure regex.yaml exists in the same directory as this script", 'YELLOW'))
        exit(1)
        
    aws_patterns = regex_config.get('aws', {})
    common_secrets = regex_config.get('common_secrets', {})

    # Collect URLs
    urls = []
    if args.url:
        urls = [args.url]
    elif args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(colorize(f"Error: File {args.input_file} not found", 'RED'))
            return
    else:
        # Read from stdin
        urls = [line.strip() for line in sys.stdin if line.strip()]
    
    if not urls:
        print(colorize("Error: No URLs to scan", 'RED'))
        return
    
    all_findings = []
    scanner = partial(scan_target, silent=args.silent, aws_patterns=aws_patterns, common_secrets=common_secrets)

    # Choose executor based on concurrency type
    if args.processes > 1:
        executor = concurrent.futures.ProcessPoolExecutor
        max_workers = args.processes
    else:
        executor = concurrent.futures.ThreadPoolExecutor
        max_workers = args.threads

    try:
        with executor(max_workers=max_workers) as exe:
            futures = {exe.submit(scanner, url): url for url in urls}
            
            try:
                for future in concurrent.futures.as_completed(futures):
                    try:
                        results = future.result()
                        all_findings.extend(results)
                    except Exception as e:
                        url = futures[future]
                        print(colorize(f"Error processing {url}: {str(e)}", 'RED'))
            except KeyboardInterrupt:
                print(colorize("\n[!] Keyboard interrupt received. Cancelling pending tasks...", 'RED'))
                # Cancel all pending futures
                for future in futures:
                    future.cancel()
                # Wait briefly for cancellation
                concurrent.futures.wait(futures, timeout=2)
                print(colorize("[!] Scan aborted. Partial results shown below.", 'RED'))

    except Exception as e:
        print(colorize(f"Unexpected error: {str(e)}", 'RED'))

    print(colorize("\n=== Scan Results ===", 'GREEN'))
    for finding in all_findings:
        print(f"\n[ {finding['type']} ] Found in {finding['source']}")
        print(f"Match: {finding['match']}")
        print(f"Context: {finding['context']}")

if __name__ == "__main__":
    main()