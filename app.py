import re
import subprocess
import json
import os
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
        if subdomain['status_code'] == '200':
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
        if subdomain['status_code'] == '200':
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
    try:
        # Fetch the page content
        response = requests.get(url)       
        response.raise_for_status()  # Raise an error for HTTP errors
        # Parse the HTML content to find the CSRF token
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = None
        # Example: Find CSRF token by looking for <input> tags with specific attributes
        csrf_input = soup.find('input', {'name': 'csrf_token'})
        if csrf_input:
            csrf_token = csrf_input.get('value')

        return csrf_token
    except ConnectionError:
        logging.error(f"Failed to establish a connection for URL: {url}")
        return None
    except Exception as e:
        logging.error(f"An error occurred while fetching CSRF token for URL {url}: {e}")
        return None

def check_csrf_vulnerability(url, csrf_token):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }

    data = {
        'csrf_token': csrf_token,  # Use the retrieved CSRF token
        'action': 'test_action'     # Replace with any necessary parameters
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        return True
    else:
        return False

def check_csrf_vulnerabilities(wayback_urls):
    csrf_results = []
    for url in wayback_urls:
        csrf_token = get_csrf_token(url)
        if csrf_token:
            is_vulnerable = check_csrf_vulnerability(url, csrf_token)
            csrf_results.append({
                'url': url,
                'csrf_vulnerable': False,
                'csrf_vulnerable': is_vulnerable
            })
        else:
            csrf_results.append({
                'url': url,
                'csrf_vulnerable': True,
                'prob': 'CSRF token not found'
            })

    return csrf_results

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
    #wayback_data = fetch_wayback_urls(validated_subdomains)
    #save_data_to_file(domain, wayback_data, 'wayback_urls.json')
    #save_urls_to_txt(wayback_data, 'wayback_urls.txt')
    #paramspider_data = asyncio.run(fetch_paramspider_urls_async(validated_subdomains))
    #save_data_to_file(domain, paramspider_data, 'paramspider_urls.json')
    #save_urls_to_txt1(paramspider_data, 'paramspider_urls.txt')
    #wayback_url = read_wayback_urls('wayback_urls.txt')
    #csrf_results = check_csrf_vulnerabilities(wayback_url)
    #save_data_to_file(domain, csrf_results, 'csrf_results.json')
    #process_paramspider_results()
    #aggregate_dalfox_results()
    #execute_clickjack()
    #run_LFI_Finder()
    #stdout, stderr = run_ssrf_finder('paramspider_urls.txt')
    #if stderr:
    #    logging.error(f'SSRF Finder execution failed: {stderr}')
    #ssrf_results = process_ssrf_output(stdout)
    #save_data_to_file(domain, ssrf_results, 'ssrf_finder_results.json')
    #wayback403 = check403()
    #save_data_to_file(domain, wayback403, 'wayback_urls_403_bypass_result.json')
    cors_scanner_result = execute_cors_scanner('subdomains.txt')
    save_data_to_file(domain , cors_scanner_result, 'cors_scanner_result.json')
    
    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        #'wayback_urls': wayback_data,
        #'paramspider_urls': paramspider_data,
        #'csrf_results': csrf_results,
        #'ssrf_results': ssrf_results,
        #'wayback_403_results': wayback403,
        'cors_scanner_result': cors_scanner_result,
    })
    



if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')