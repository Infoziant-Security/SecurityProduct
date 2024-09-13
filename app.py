import re
import subprocess
import json
import dns.resolver
import os
import pexpect
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from logging.config import dictConfig
import asyncio
from urllib.request import Request, urlopen
import urllib
import requests
from termcolor import colored
from urllib.parse import urlparse
import random
import urllib.error
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError


# Configure logging
dictConfig({
    'version': 1,
    'formatters': {'default': {
        'format': '[%(asctime)s] %(levelname)s in %(module)s: %(message)s',
    }},
    'handlers': {'wsgi': {
        'class': 'logging.StreamHandler',
        'formatter': 'default'
    }},
    'root': {
        'level': 'INFO',
        'handlers': ['wsgi']
    }
})

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

def run_subprocess(command):
    try:
        return subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
    except subprocess.CalledProcessError as e:
        logging.error(f"Subprocess {command} failed with {e}")
        return None

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def find_subdomains(domain, tool):
    subdomains = set()
    command = ['assetfinder', domain] if tool == 'assetfinder' else ['subfinder', '-d', domain]
    result = run_subprocess(command)
    if result:
        lines = result.stdout.split('\n')
        for line in lines:
            subdomain = line.strip()
            if subdomain.endswith(domain):
                subdomains.add(subdomain)
    return subdomains

def validate_subdomains(subdomains):
    with open('subdomains.txt', 'w') as f:
        f.write('\n'.join(f'http://{sub}' for sub in subdomains))

    result = run_subprocess(['httpx', '-status-code', '-l', 'subdomains.txt'])
    validated_subdomains = []
    if result:
        for line in result.stdout.splitlines():
            if 'http' in line:
                parts = line.split()
                url = parts[0]
                status_code = strip_ansi_codes(parts[1].strip('[]'))
                validated_subdomains.append({
                    'subdomain': url,
                    'status_code': status_code
                })
    return validated_subdomains

def fetch_wayback_urls(validated_subdomains):
    wayback_data = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] == '200' or subdomain['status_code'] == '301':
            result = run_subprocess(['waybackurls', subdomain['subdomain']])
            if result:
                urls = result.stdout.splitlines()
                wayback_data[subdomain['subdomain']] = urls
            else:
                logging.error(f"Failed to fetch wayback URLs for {subdomain['subdomain']}")
    return wayback_data

async def fetch_paramspider_urls_async(validated_subdomains):
    paramspider_data = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] == '200' or subdomain['status_code'] == '301':
            domain_name = subdomain['subdomain'].split("//")[-1]
            result = run_subprocess(['paramspider', '-d', domain_name])
            if result:
                output_file_path = f"results/{domain_name}.txt"
                if os.path.exists(output_file_path):
                    with open(output_file_path, 'r', encoding='utf-8') as file:
                        urls = file.readlines()
                    paramspider_data[subdomain['subdomain']] = [url.strip() for url in urls]
                else:
                    logging.error(f"Expected output file not found: {output_file_path}")
            else:
                logging.error(f"ParamSpider failed for {subdomain['subdomain']}")
    return paramspider_data

def save_urls_to_txt1(paramspider_data, filename):
    try:
        with open(filename, 'w') as file:
            for subdomain, urls in paramspider_data.items():
                for url in urls:
                    file.write(url + '\n')
        logging.info(f"URLs successfully saved to {filename}")
    except Exception as e:
        logging.error(f"Error writing to file {filename}: {e}")

def save_data_to_file(domain, data, filename):
    path = os.path.join(os.getenv('DATA_DIR', './'), filename)
    with open(path, 'a+', encoding='utf-8') as file:    
        file.seek(0)
        try:
            existing_data = json.load(file)
        except json.JSONDecodeError:
            existing_data = {}
        existing_data[domain] = data
        file.seek(0)
        json.dump(existing_data, file, indent=4)
        file.truncate()

def save_urls_to_txt(wayback_data, filename):
    try:
        with open(filename, 'w') as file:
            for subdomain, urls in wayback_data.items():
                for url in urls:
                    file.write(url + '\n')
        logging.info(f"URLs successfully saved to {filename}")
    except Exception as e:
        logging.error(f"Error writing to file {filename}: {e}")

def run_dalfox(input_file, output_file):
    command = ['dalfox', 'file', input_file, '-o', output_file]
    try:
        subprocess.run(command, check=True)
        logging.info(f"Dalfox scanning completed for {input_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Dalfox scanning failed for {input_file} with error {e}")

def process_paramspider_results():
    results_dir = './results'
    dalfox_results_dir = './dalfox_results'
    os.makedirs(dalfox_results_dir, exist_ok=True)

    for filename in os.listdir(results_dir):
        if filename.endswith('.txt'):
            input_path = os.path.join(results_dir, filename)
            output_path = os.path.join(dalfox_results_dir, f'dalfox_{filename}')
            run_dalfox(input_path, output_path)


def aggregate_dalfox_results():
    dalfox_results_dir = './dalfox_results'
    aggregate_file_path = os.path.join(dalfox_results_dir, 'aggregate_results.txt')
    
    logging.info(f"Aggregating results in directory: {dalfox_results_dir}")
    logging.info(f"Aggregate file path: {aggregate_file_path}")
    
    try:
        with open(aggregate_file_path, 'w') as aggregate_file:
            for filename in os.listdir(dalfox_results_dir):
                if filename.startswith('dalfox_') and filename.endswith('.txt'):
                    file_path = os.path.join(dalfox_results_dir, filename)
                    logging.info(f"Processing file: {file_path}")
                    with open(file_path, 'r') as file:
                        results = file.read()
                        if results.strip():  # Only write if there's content
                            aggregate_file.write(f"Results from {filename}:\n{results}\n\n")
        process_vulnerability_results(dalfox_results_dir, 'aggregate_results.txt')
    except Exception as e:
        logging.error(f"Error during aggregation: {e}")

def process_vulnerability_results(folder_path, file_name):
    xss_results = []
    open_redirect_results = []

    file_path = os.path.join(folder_path, file_name)
    logging.info(f"Processing vulnerability results from file: {file_path}")
    
    try:
        with open(file_path, 'r') as file:
            for line in file:
                if '[POC][G][GET][BAV/OR]' in line:
                    open_redirect_results.append(line.strip())
                elif '[POC][V][GET]' in line:
                    xss_results.append(line.strip())
        
        with open(os.path.join(folder_path, 'xss_vulnerabilities.json'), 'w') as xss_file:
            json.dump(xss_results, xss_file, indent=4)
        
        with open(os.path.join(folder_path, 'open_redirect_vulnerabilities.json'), 'w') as open_redirect_file:
            json.dump(open_redirect_results, open_redirect_file, indent=4)
    except Exception as e:
        logging.error(f"Error during vulnerability processing: {e}")
                        
def run_ssrf_finder(input_file):
    command = f'type {input_file} | .\\ssrf-finder.exe'
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout, result.stderr

def process_ssrf_output(output):
    results = []
    lines = output.split('\n')
    for line in lines:
        if line.strip() == "":
            continue
        if "response code:" in line or "failed to fetch:" in line:
            parts = line.split(' ', 1)
            if len(parts) == 2:
                results.append({
                    "url": parts[1],
                    "message": parts[0]
                })
    return results                        


def execute_clickjack():
    logging.info("Execution started")
    hdr = {'User-Agent': 'Mozilla/5.0'}
    results = []

    # List of common asset file extensions to exclude
    asset_extensions = ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', 
                        '.js', '.css', '.ico', '.woff', '.woff2', 
                        '.ttf', '.eot', '.otf', '.pdf', '.zip', '.rar', 
                        '.exe', '.dmg', '.tar.gz', '.mp3', '.mp4', 
                        '.avi', '.mov', '.mkv', '.flv', '.webm')

    with open("wayback_urls.txt", 'r') as d:
        try:
            for target in d.readlines():
                t = target.strip('\n')
                if not t.startswith(("http://", "https://")):
                    t = "https://" + t

                # Validate the URL to exclude asset types
                parsed_url = urlparse(t)
                if parsed_url.path.endswith(asset_extensions):
                    print(colored(f"Skipping asset URL: {t}", "yellow"))
                    continue

                try:
                    req = Request(t, headers=hdr)
                    data = urlopen(req, timeout=10)
                    headers = data.info()

                    if "X-Frame-Options" not in headers and "x-frame-options" not in headers:
                        print(colored(f"Target: {t} is Vulnerable", "green"))
                        filename = parsed_url.netloc
                        poc = f"""
                        <html>
                        <head><title>Clickjack POC page</title></head>
                        <body>
                        <p>Website is vulnerable to clickjacking!</p>
                        <iframe src="{t}" width="500" height="500"></iframe>
                        </body>
                        </html>
                        """
                        if ":" in filename:
                            filename = filename.split(':')[0]
                        
                        with open(filename + ".html", "w") as pf:
                            pf.write(poc)

                        print(colored(f"Clickjacking POC file Created Successfully, Open {filename}.html to get the POC", "blue"))
                        
                        results.append({"url": t, "status": "Vulnerable"})
                    else:
                        print(colored(f"Target: {t} is not Vulnerable", "red"))
                        results.append({"url": t, "status": "Not Vulnerable"})
                        
                except KeyboardInterrupt:
                    print("No Worries, I'm here to handle your Keyboard Interrupts\n")
                except urllib.error.URLError as e:
                    print(f"Target {t} has some HTTP Errors via http://, lets try https:// ", e)
                except requests.HTTPError as exception:
                    print(f"Target {t} has some HTTP Errors :--> ", exception)
                except Exception as e:
                    print("Exception Occurred with Description ----> ", e)
                    raise Exception("Target Didn't Respond")

            print("All Targets Tested Successfully!!")

        except Exception as e:
            print(e)
    
    with open("clickjack_results.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
        print("Results written to clickjack_results.json")

def check_lfi_vulnerability(url):
    print("Trying payloads list, please wait...")
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    chrome_options.add_argument('--no-sandbox')
    chrome_options.add_argument('--disable-dev-shm-usage')
    browser = webdriver.Chrome(options=chrome_options)
    browser.maximize_window()
    count = 0
    vulnerable_urls = []
    with open("lfi.txt", "r", encoding="UTF-8") as file:
        payloads = file.readlines()
        try:
            while count < len(payloads):
                target_url = url + payloads[count]
                browser.get(target_url)
                print("Testing: " + payloads[count])
                time.sleep(random.randint(1, 3))
                count += 1
                if "root:x:0:0:root" in browser.page_source:
                    vulnerable_urls.append(target_url)
                    print("Vuln Url: " + target_url)
                if count == len(payloads):
                    browser.close()
        except Exception as e:
            logging.error(f"An error occurred while checking LFI vulnerability: {e}")

    browser.quit()
    return vulnerable_urls

def run_LFI_Finder():
    with open("paramspider_urls.txt", "r") as f:
        urls = f.readlines()
        for url in urls:
            url = str(url).strip()
            if url == "":
                continue
            elif url[-1] == '/' or url[-1] == '\\':
                url = url[:-1]
            print("Checking Vulnerabilities for the url: " + url)
            vulnerabilities = check_lfi_vulnerability(url)
            print("Vulnerable urls are: ")
            for v in vulnerabilities:
                print(v)
    return "Thank you"

def validate_wayback_urls(wayback_urls):
    validated_wayback_urls = {}
    f = open("wayback_urls.txt", "r")
    data = f.read()
    wayback_data = data.split("\n")
    
    for u in wayback_data:
        if u.strip():  # Check if the URL is not empty
            result = subprocess.run(["httpx", "-silent", "-status-code", u], capture_output=True, text=True)
            status_code = result.stdout.strip()
            app.logger.info(f'{u} - {status_code}')
            validated_wayback_urls[u] = status_code
    
    return validated_wayback_urls

def find_403_from_wayback(wayback_dict):
    wayback_403 = {}
    for u in wayback_dict:
        if '403' in str(wayback_dict[u]):
            result = subprocess.run(['bypass-403.sh', u], shell=True, stdout=subprocess.PIPE)
            wayback_403[u] = result.stdout.decode('utf-8').strip()
    app.logger.info(wayback_403)
    
    
    
    return wayback_403

def read_wayback_urls(filename):
    with open(filename, "r") as f:
        wayback_data = f.read().splitlines()
    return wayback_data

def execute_cors_scanner(filename):
    cors_result = {}
    with open(filename, "r") as f:
        subdomain_list = f.read().splitlines()
    for u in subdomain_list:
        ret = subprocess.run(["cors", "-u", u], stdout=subprocess.PIPE)
        cors_result[u] = ret.stdout.decode('utf-8').strip()
        app.logger.info(ret.stdout)
    return cors_result


def check403():
    # 403 Bypass check
    wayback_data = read_wayback_urls('wayback_urls.txt')
    app.logger.info("Wayback data extracted")
    validated_wayback_urls = validate_wayback_urls(wayback_data)
    wayback_403_data = find_403_from_wayback(validated_wayback_urls)
    app.logger.info("Wayback 403 Bypass check executed")
    return wayback_403_data
    return 'Wayback 403 Bypass check executed and results saved'\
        
def get_csrf_token(url):
    """Fetch CSRF token from a given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for bad responses
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_input = soup.find('input', {'name': 'csrf_token'})
        if csrf_input:
            return csrf_input.get('value')
        else:
            logging.warning(f"No CSRF token found at {url}")
            return None
    except requests.RequestException as e:
        logging.error(f"Request failed for URL {url}: {e}")
        return None

def check_csrf_vulnerability(url, csrf_token):
    """Check if a URL is vulnerable to CSRF."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }
    data = {
        'csrf_token': csrf_token,
        'action': 'test_action'  # Replace with any necessary parameters
    }
    try:
        response = requests.post(url, headers=headers, data=data)
        return response.status_code == 200
    except requests.RequestException as e:
        logging.error(f"Failed to post data to {url}: {e}")
        return False

def check_csrf_vulnerabilities(urls):
    """Check a list of URLs for CSRF vulnerabilities."""
    results = []
    for url in urls:
        csrf_token = get_csrf_token(url)
        if csrf_token:
            is_vulnerable = check_csrf_vulnerability(url, csrf_token)
            results.append({'url': url, 'csrf_vulnerable': is_vulnerable})
        else:
            results.append({'url': url, 'csrf_vulnerable': True, 'prob': 'CSRF token not found'})
    return results

vulnerable_versions = {
    'Apache': [
        '2.4.49', '2.4.50', '2.4.46', '2.4.41', '2.4.39', '2.4.10', '2.2.34'
    ],
    'Nginx': [
        '1.18.0', '1.19.0', '1.16.1', '1.14.2', '1.12.2', '1.10.3'
    ],
    'Microsoft-IIS': [
        '10.0', '8.5', '7.5'
    ],
    'LiteSpeed': [
        '5.4.5', '5.4.1', '5.3.8', '5.2.6'
    ],
    'OpenResty': [
        '1.15.8.3', '1.13.6.2', '1.11.2.5'
    ],
    'Caddy': [
        '2.2.1', '2.1.1', '1.0.3', '0.11.5'
    ]
}

def check_version_vulnerability(server_header):
    for server, versions in vulnerable_versions.items():
        if server in server_header:
            for version in versions:
                if version in server_header:
                    return True
    return False

def fetch_server_version_info(validated_subdomains):
    server_info = {}
    for subdomain in validated_subdomains:
        try:
            response = requests.head(subdomain['subdomain'], timeout=5)
            server_header = response.headers.get('Server', 'Unknown')
            is_vulnerable = check_version_vulnerability(server_header)
            server_info[subdomain['subdomain']] = {
                'server': server_header,
                'vulnerable': is_vulnerable
            }
        except requests.RequestException as e:
            logging.error(f"Error fetching server info for {subdomain['subdomain']}: {e}")
            server_info[subdomain['subdomain']] = {
                'server': 'Error',
                'vulnerable': True
            }
    return server_info

def fetch_spf_dmarc_records(validated_subdomains):
    spf_dmarc_records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for subdomain in validated_subdomains:
        domain = subdomain['subdomain'].split("//")[-1]
        spf_record = []
        dmarc_record = []
        spf_vulnerable = True
        dmarc_vulnerable = True

        try:
            txt_answers = resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt_data = str(rdata)
                if 'v=spf1' in txt_data:
                    spf_record.append(txt_data)
                    if '+all' not in txt_data:
                        spf_vulnerable = False

            if not spf_record:
                spf_vulnerable = True

            dmarc_answers = resolver.resolve('_dmarc.' + domain, 'TXT')
            for rdata in dmarc_answers:
                txt_data = str(rdata)
                if 'v=DMARC1' in txt_data:
                    dmarc_record.append(txt_data)
                    if 'p=reject' in txt_data:
                        dmarc_vulnerable = False
                    elif 'p=quarantine' in txt_data:
                        dmarc_vulnerable = False

            if not dmarc_record:
                dmarc_vulnerable = True

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
            logging.error(f"Error fetching SPF/DMARC records for {domain}: {e}")

        spf_dmarc_records[subdomain['subdomain']] = {
            'spf': spf_record,
            'spf_vulnerable': spf_vulnerable,
            'dmarc': dmarc_record,
            'dmarc_vulnerable': dmarc_vulnerable
        }
    return spf_dmarc_records

def run_shcheck(subdomain):
    original_dir = os.getcwd()
    try:
        # Change to the shcheck directory
        os.chdir('shcheck')
        # Execute shcheck.py
        result = subprocess.run(['python', 'shcheck.py', subdomain], capture_output=True, text=True, check=True)
        # Change back to the original directory
        os.chdir(original_dir)
        # Ensure the output is valid
        output = result.stdout.strip()
        if output:
            return parse_shcheck_output(output)
        else:
            raise ValueError("Empty output from shcheck")
    except subprocess.CalledProcessError as e:
        os.chdir(original_dir)
        logging.error(f"shcheck failed for {subdomain} with error {e}")
        return {'error': 'shcheck execution failed'}
    except Exception as e:
        os.chdir(original_dir)
        logging.error(f"Unexpected error: {e}")
        return {'error': str(e)}

def parse_shcheck_output(output):
    # Initialize the dictionary to hold the extracted information
    parsed_output = {"effective_url": "", "missing_headers": []}
    lines = output.split("\n")
    for line in lines:
        if "[*] Effective URL:" in line:
            parsed_output["effective_url"] = line.split(": ")[1].strip()
        elif "[!] Missing security header:" in line:
            parsed_output["missing_headers"].append(line.split(": ")[1].strip())
    return parsed_output

def fetch_security_headers(validated_subdomains):
    security_headers = {}
    for subdomain in validated_subdomains:
        headers_result = run_shcheck(subdomain['subdomain'])
        security_headers[subdomain['subdomain']] = headers_result
    return security_headers

import pexpect

def run_commix(url):
    command = f'docker run -it commix --url={url}'
    child = pexpect.spawn(command)
    log_output = []

    try:
        while True:
            index = child.expect([pexpect.TIMEOUT, pexpect.EOF, 'Do you want to follow? [Y/n] >'])
            if index == 0:
                log_output.append(child.before.decode('utf-8'))
                break
            elif index == 1:
                log_output.append(child.before.decode('utf-8'))
                break
            elif index == 2:
                child.sendline('y')
                log_output.append(child.before.decode('utf-8') + 'y\n')
    except Exception as e:
        logging.error(f"Error running commix: {e}")

    # Filter the log output to start from the specified message
    filtered_output = []
    start_logging = False
    for line in log_output:
        if 'Testing connection to the target URL.' in line:
            start_logging = True
        if start_logging:
            filtered_output.append(line)

    return ''.join(filtered_output)

def run_commix_on_wayback_urls(domain):
    wayback_urls = read_wayback_urls('wayback_urls.txt')
    commix_results = []
    for url in wayback_urls:
        commix_output = run_commix(url)
        commix_results.append({
            'url': url,
            'output': commix_output
        })
    commix_output_file = f'commix_results_{domain}.json'
    with open(commix_output_file, 'w') as file:
        json.dump({'commix_output': commix_results}, file, indent=4)
    return commix_results, commix_output_file


def run_smuggler(input_file):
    smuggler_dir = 'smuggler'
    payload_dir = os.path.join(smuggler_dir, 'payload')
    
    try:
        with open(input_file, 'r') as file:
            urls = file.read().splitlines()
        
        for url in urls:
            command = ['python3', os.path.join(smuggler_dir, 'smuggler.py'), '--url', url]
            subprocess.run(command, check=True)
        
        logging.info(f"Smuggler executed successfully with input file {input_file}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Smuggler execution failed: {e}")
        return None
    
    return payload_dir


def aggregate_smuggler_results(payload_dir):
    aggregated_results = {}
    for filename in os.listdir(payload_dir):
        file_path = os.path.join(payload_dir, filename)
        with open(file_path, 'r') as file:
            content = file.read()
            aggregated_results[filename] = content
    
    output_file = 'smuggler_results.json'
    with open(output_file, 'w') as json_file:
        json.dump(aggregated_results, json_file, indent=4)
    
    return output_file

def fetch_js_urls_from_website(url):
    """
    Fetch JavaScript URLs from the given website URL.
    
    Args:
        url (str): The URL of the website to scan.
    
    Returns:
        list: A list of JavaScript file URLs.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        js_urls = []
        for script in soup.find_all('script'):
            src = script.get('src')
            if src:
                if src.startswith('http'):
                    js_urls.append(src)
                else:
                    js_urls.append(urllib.parse.urljoin(url, src))
        return js_urls
    except requests.RequestException as e:
        logging.error(f"Failed to fetch JavaScript URLs from {url}: {e}")
        return []


def run_retire_js_on_urls(js_urls):
    """
    Run retire.js on the given JavaScript URLs.
    
    Args:
        js_urls (list): List of JavaScript file URLs to scan.
    
    Returns:
        dict: The JSON output from retire.js containing the scan results.
    """
    results = {}
    for js_url in js_urls:
        command = ['retire', '--path', js_url, '--outputformat', 'json']
        result = run_subprocess(command)
        if result:
            try:
                retire_js_output = json.loads(result.stdout)
                results[js_url] = retire_js_output
            except json.JSONDecodeError as e:
                logging.error(f"Failed to parse retire.js output for {js_url}: {e}")
                results[js_url] = {'error': 'Failed to parse retire.js output'}
        else:
            logging.error(f"retire.js execution failed for {js_url}")
            results[js_url] = {'error': 'retire.js execution failed'}
    return results


def run_autopoisoner(subdomain):
    """
    Runs the AutoPoisoner tool for the given subdomain and captures the output.
    
    Args:
        subdomain (str): The subdomain to run AutoPoisoner on.
    
    Returns:
        dict: The parsed result from AutoPoisoner.
    """
    try:
        # Command to run AutoPoisoner
        command = ['python3', 'autopoisoner.py', '--url', subdomain]
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Parse the JSON output
        output = result.stdout.strip()
        if output:
            parsed_output = json.loads(output)
            return parsed_output
        else:
            logging.error(f"No output from AutoPoisoner for {subdomain}")
            return {'url': subdomain, 'vulnerable': False, 'error': 'No output from AutoPoisoner'}
    except subprocess.CalledProcessError as e:
        logging.error(f"AutoPoisoner execution failed for {subdomain}: {e}")
        return {'url': subdomain, 'vulnerable': False, 'error': 'Execution failed'}
    except Exception as e:
        logging.error(f"Unexpected error running AutoPoisoner on {subdomain}: {e}")
        return {'url': subdomain, 'vulnerable': False, 'error': str(e)}


def fetch_autopoisoner_results(validated_subdomains):
    """
    Run AutoPoisoner for each validated subdomain and collect the results.
    
    Args:
        validated_subdomains (list): List of validated subdomains.
    
    Returns:
        dict: The AutoPoisoner results for each subdomain.
    """
    autopoisoner_results = {}
    for subdomain in validated_subdomains:
        subdomain_url = subdomain['subdomain']
        autopoisoner_result = run_autopoisoner(subdomain_url)
        autopoisoner_results[subdomain_url] = autopoisoner_result
    
    return autopoisoner_results

def run_sqlmap_on_paramspider_urls(domain):
    sqlmap_dir = 'sqlmap'  # Directory where sqlmap.py is located
    paramspider_urls_file = 'paramspider_urls.txt'
    sqlmap_results = []

    try:
        with open(paramspider_urls_file, 'r') as file:
            paramspider_urls = file.read().splitlines()

        for url in paramspider_urls:
            command = ['python3', os.path.join(sqlmap_dir, 'sqlmap.py'), '-u', url, '--batch', '--forms', '--output-format=json']
            result = subprocess.run(command, capture_output=True, text=True)

            # Parse and store the SQLMap results
            if result.stdout:
                try:
                    sqlmap_output = json.loads(result.stdout)  # Assuming SQLMap outputs JSON
                    sqlmap_results.append({
                        'url': url,
                        'vulnerable': bool(sqlmap_output.get('vulnerabilities', [])),
                        'details': sqlmap_output
                    })
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse SQLMap output for {url}")
                    sqlmap_results.append({
                        'url': url,
                        'vulnerable': False,
                        'details': 'Error parsing output'
                    })
            else:
                logging.error(f"No output from SQLMap for {url}")
                sqlmap_results.append({
                    'url': url,
                    'vulnerable': False,
                    'details': 'No output'
                })

        # Save the results to a JSON file
        output_file = f'sqlmap_results_{domain}.json'
        with open(output_file, 'w') as json_file:
            json.dump({'sqlmap_output': sqlmap_results}, json_file, indent=4)

        return sqlmap_results, output_file

    except Exception as e:
        logging.error(f"Error running SQLMap on ParamSpider URLs: {e}")
        return None, None

def run_nmap_on_paramspider_urls(domain):
    nmap_results = []
    paramspider_urls_file = 'paramspider_urls.txt'

    try:
        with open(paramspider_urls_file, 'r') as file:
            paramspider_urls = file.read().splitlines()

        for url in paramspider_urls:
            command = ['nmap', '-Pn', '-sV', '-oX', '-', url]  # XML output from Nmap
            result = subprocess.run(command, capture_output=True, text=True)

            # Parse Nmap XML output and convert it to JSON
            if result.stdout:
                try:
                    nmap_xml = result.stdout
                    # Parsing the XML output from Nmap using xmltodict
                    nmap_data = xmltodict.parse(nmap_xml)
                    nmap_results.append({
                        'url': url,
                        'ports': nmap_data.get('nmaprun', {}).get('host', {}).get('ports', {}),
                        'vulnerable': bool(nmap_data.get('nmaprun', {}).get('host', {}).get('ports', {}).get('port'))
                    })
                except Exception as e:
                    logging.error(f"Failed to parse Nmap output for {url}: {e}")
                    nmap_results.append({
                        'url': url,
                        'vulnerable': False,
                        'details': 'Error parsing output'
                    })
            else:
                logging.error(f"No output from Nmap for {url}")
                nmap_results.append({
                    'url': url,
                    'vulnerable': False,
                    'details': 'No output'
                })

        # Save the results to a JSON file
        output_file = f'nmap_results_{domain}.json'
        with open(output_file, 'w') as json_file:
            json.dump({'nmap_output': nmap_results}, json_file, indent=4)

        return nmap_results, output_file

    except Exception as e:
        logging.error(f"Error running Nmap on ParamSpider URLs: {e}")
        return None, None

def run_sstimap_on_paramspider_urls(domain):
    sstimap_results = []
    paramspider_urls_file = 'paramspider_urls.txt'

    try:
        with open(paramspider_urls_file, 'r') as file:
            paramspider_urls = file.read().splitlines()

        for url in paramspider_urls:
            command = ['python3', 'sstimap.py', '-u', url]  # Run SSTImap with the URL
            result = subprocess.run(command, capture_output=True, text=True, cwd='SSTImap')  # Ensure SSTImap directory

            if result.stdout:
                try:
                    # Parse SSTImap output (assuming it's in plain text or JSON format)
                    sstimap_output = result.stdout.strip()
                    if 'Vulnerable' in sstimap_output:
                        sstimap_results.append({
                            'url': url,
                            'vulnerable': True,
                            'details': sstimap_output
                        })
                    else:
                        sstimap_results.append({
                            'url': url,
                            'vulnerable': False,
                            'details': sstimap_output
                        })
                except Exception as e:
                    logging.error(f"Failed to parse SSTImap output for {url}: {e}")
                    sstimap_results.append({
                        'url': url,
                        'vulnerable': False,
                        'details': 'Error parsing output'
                    })
            else:
                logging.error(f"No output from SSTImap for {url}")
                sstimap_results.append({
                    'url': url,
                    'vulnerable': False,
                    'details': 'No output'
                })

        # Save the results to a JSON file
        output_file = f'sstimap_results_{domain}.json'
        with open(output_file, 'w') as json_file:
            json.dump({'sstimap_output': sstimap_results}, json_file, indent=4)

        return sstimap_results, output_file

    except Exception as e:
        logging.error(f"Error running SSTImap on ParamSpider URLs: {e}")
        return None, None


@app.route('/api/subdomains', methods=['POST'])
def get_subdomains():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    subdomains_assetfinder = find_subdomains(domain, 'assetfinder')
    subdomains_subfinder = find_subdomains(domain, 'subfinder')
    subdomains = list(subdomains_assetfinder.union(subdomains_subfinder))
    validated_subdomains = validate_subdomains(subdomains)
    save_data_to_file(domain, validated_subdomains, 'validated_subdomains.json')
    wayback_data = fetch_wayback_urls(validated_subdomains)
    save_data_to_file(domain, wayback_data, 'wayback_urls.json')
    save_urls_to_txt(wayback_data, 'wayback_urls.txt')
    paramspider_data = asyncio.run(fetch_paramspider_urls_async(validated_subdomains))
    save_data_to_file(domain, paramspider_data, 'paramspider_urls.json')
    save_urls_to_txt1(paramspider_data, 'paramspider_urls.txt')
    server_version_info = fetch_server_version_info(validated_subdomains)
    save_data_to_file(domain, server_version_info, 'server_version_info.json')
    spf_dmarc_records = fetch_spf_dmarc_records(validated_subdomains)
    save_data_to_file(domain, spf_dmarc_records, 'spf_dmarc_records.json')
    security_headers = fetch_security_headers(validated_subdomains)
    save_data_to_file(domain, security_headers, 'security_headers.json') 
    wayback_url = read_wayback_urls('wayback_urls.txt')
    csrf_results = check_csrf_vulnerabilities(wayback_url)
    save_data_to_file(domain, csrf_results, 'csrf_results.json')
    process_paramspider_results()
    aggregate_dalfox_results()
    stdout, stderr = run_ssrf_finder('paramspider_urls.txt')
    if stderr:
        logging.error(f'SSRF Finder execution failed: {stderr}')
    ssrf_results = process_ssrf_output(stdout)
    save_data_to_file(domain, ssrf_results, 'ssrf_finder_results.json')
    execute_clickjack()
    run_LFI_Finder()
    retire_js_results = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] in ['200', '301']:
            js_urls = fetch_js_urls_from_website(subdomain['subdomain'])
            if js_urls:
                retire_js_results[subdomain['subdomain']] = run_retire_js_on_urls(js_urls)
    save_data_to_file(domain, retire_js_results, 'retire_js_results.json')
    smuggler_payload_dir = run_smuggler('wayback_urls.txt')
    if smuggler_payload_dir:
        smuggler_results_file = aggregate_smuggler_results(smuggler_payload_dir)
    else:
        smuggler_results_file = None
    commix_results, commix_output_file = run_commix_on_wayback_urls(domain)
    wayback403 = check403()
    save_data_to_file(domain, wayback403, 'wayback_urls_403_bypass_result.json')
    cors_scanner_result = execute_cors_scanner('subdomains.txt')
    save_data_to_file(domain , cors_scanner_result, 'cors_scanner_result.json')
    autopoisoner_results = fetch_autopoisoner_results(validated_subdomains)
    save_data_to_file(domain, autopoisoner_results, 'autopoisoner_results.json')
    sqlmap_results, sqlmap_output_file = run_sqlmap_on_paramspider_urls(domain)
    nmap_results, nmap_output_file = run_nmap_on_paramspider_urls(domain)
    sstimap_results, sstimap_output_file = run_sstimap_on_paramspider_urls(domain)
    
    
    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        'wayback_urls': wayback_data,
        'paramspider_urls': paramspider_data,
        'csrf_results': csrf_results,
        'ssrf_results': ssrf_results,
        'wayback_403_results': wayback403,
        'cors_scanner_result': cors_scanner_result,
        'server_version_info': server_version_info,
        'spf_dmarc_records': spf_dmarc_records, 
        'security_headers': security_headers,
        'commix_results': commix_results,
        'commix_output_file': commix_output_file,
        'retire_js_results': retire_js_results,
        'sqlmap_results': sqlmap_results,  
        'sqlmap_output_file': sqlmap_output_file,
        'autopoisoner_results': autopoisoner_results, 
        'nmap_results': nmap_results, 
        'nmap_output_file': nmap_output_file,  
        'sstimap_results': sstimap_results,  
        'sstimap_output_file': sstimap_output_file, 
    })
    

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')    