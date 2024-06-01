import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError, Timeout, HTTPError
import argparse
import logging
import re
import concurrent.futures
import json
import os

# Colors for terminal output
green = '\033[92m'
yellow = '\033[93m'
end = '\033[0m'
red = end = '\033[0m'
good = f'{green}[+]{end}'
info = f'{yellow}[i]{end}'
bad = f'{red}[-]{end}'

lightning = '\033[93;5m⚡\033[0m'

def banner():
    print(f'''
     {yellow}⚡ {green}CSRF Detector{yellow}  ⚡{end}
    ''')

banner()

parser = argparse.ArgumentParser(description="Check CSRF vulnerabilities for given URLs.")
parser.add_argument('-u', '--url', help="Target URL to check for CSRF vulnerability.", dest='target')
parser.add_argument('-f', '--file', help="File containing a list of URLs to check.", dest='file')
parser.add_argument('-t', '--threads', help='Number of threads', dest='threads', type=int, default=5)
parser.add_argument('--timeout', help='HTTP request timeout', dest='timeout', type=int, default=10)
args = parser.parse_args()

if not args.target and not args.file:
    print('\n' + parser.format_help().lower())
    quit()

# Load hash patterns from JSON
def load_hash_patterns(filename='hashes.json'):
    if not os.path.exists(filename):
        logging.error(f"File not found: {filename}")
        return []
    with open(filename, 'r') as file:
        return json.load(file)

hash_patterns = load_hash_patterns()

def get_csrf_token(url):
    try:
        response = requests.get(url, timeout=args.timeout)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = None

        # Common CSRF token names
        token_names = [
            'csrf_token', 'csrf', '_csrf', 'csrfmiddlewaretoken', 'authenticity_token',
            '_token', 'csrf-token', '_csrf_token', '_csrf_param', 'request_token',
            'csrf_protection', 'csrf_token_name', 'csrf-token-name', 'csrfparam', 'csrfvalue',
            'csrf-value', 'security_token', 'xsrf_token', '_xsrf', 'form_token',
            'csrf_token_id', 'csrf_token_value', 'csrfname', 'csrftoken', 'token',
            '__RequestVerificationToken', 'stoken', 'secure_token'
        ]

        # Check for CSRF tokens in input fields
        for token_name in token_names:
            csrf_input = soup.find('input', {'name': token_name})
            if csrf_input:
                csrf_token = csrf_input.get('value')
                logging.info(f"CSRF token found in input field: {csrf_token}")
                return csrf_token

        # Check for CSRF tokens in meta tags
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            if 'csrf' in meta.get('name', '').lower() or 'xsrf' in meta.get('name', '').lower():
                csrf_token = meta.get('content')
                if csrf_token:
                    logging.info(f"CSRF token found in meta tag: {csrf_token}")
                    return csrf_token

        # Check for CSRF tokens in JavaScript variables
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                match = re.search(r"var\s+(csrfToken|_csrf|csrf|xsrfToken|__RequestVerificationToken)\s*=\s*['\"]([^'\"]+)['\"]", script.string)
                if match:
                    csrf_token = match.group(2)
                    logging.info(f"CSRF token found in JavaScript: {csrf_token}")
                    return csrf_token

        # Check for CSRF tokens in cookies
        for cookie in response.cookies:
            if 'csrf' in cookie.name.lower() or 'xsrf' in cookie.name.lower():
                csrf_token = cookie.value
                logging.info(f"CSRF token found in cookie: {csrf_token}")
                return csrf_token

        logging.info("No CSRF token found using common methods.")
        return csrf_token
    except ConnectionError:
        logging.error(f"Failed to establish a connection for URL: {url}")
        return None
    except Timeout:
        logging.error(f"Request timed out for URL: {url}")
        return None
    except HTTPError as http_err:
        logging.error(f"HTTP error occurred for URL {url}: {http_err}")
        return None
    except Exception as e:
        logging.error(f"An error occurred while fetching CSRF token for URL {url}: {e}")
        return None

def match_token_pattern(token):
    matches = []
    for pattern in hash_patterns:
        if re.match(pattern['regex'], token):
            matches.extend(pattern['matches'])
    return matches

def check_csrf_vulnerability(url, csrf_token):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }
    data = {
        'csrf_token': csrf_token,
        'action': 'test_action'
    }
    response = requests.post(url, headers=headers, data=data)
    return response.status_code == 200

def process_url(url):
    logging.info(f"Checking CSRF vulnerability for: {url}")
    csrf_token = get_csrf_token(url)
    if csrf_token:
        matches = match_token_pattern(csrf_token)
        if matches:
            logging.info(f"{info} CSRF token matches the pattern(s) of: {', '.join(matches)}")
        if check_csrf_vulnerability(url, csrf_token):
            logging.info(f"{good} CSRF vulnerability found at: {url}")
        else:
            logging.info(f"{bad} No CSRF vulnerability found at: {url}")
    else:
        logging.info(f"{bad} CSRF token not found for URL: {url}")

def main():
    urls = []
    if args.target:
        urls.append(args.target)
    elif args.file:
        try:
            with open(args.file, 'r') as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            logging.error(f"File not found: {args.file}")
            return

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_url, url) for url in urls]
        for future in concurrent.futures.as_completed(futures):
            future.result()

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()