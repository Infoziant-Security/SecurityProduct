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
import argparse
from sys import exit
import urllib
import requests
import urllib.request
from termcolor import colored
from urllib.parse import urlparse
import random
from time import sleep
import time
from selenium import webdriver
import sys
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import NoSuchElementException

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
    
    with open(aggregate_file_path, 'w') as aggregate_file:
        for filename in os.listdir(dalfox_results_dir):
            if filename.startswith('dalfox_') and filename.endswith('.txt'):
                file_path = os.path.join(dalfox_results_dir, filename)
                with open(file_path, 'r') as file:
                    results = file.read()
                    if results.strip():  # Only write if there's content
                        aggregate_file.write(f"Results from {filename}:\n{results}\n\n")

def run_bolt(subdomain):
    command = ['python', 'bolt.py', '-u', subdomain, '-l', '2']
    original_cwd = os.getcwd()
    bolt_directory = os.path.join(original_cwd, 'bolt')
    try:
        os.chdir(bolt_directory)
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        os.chdir(original_cwd)  # Return to the original directory
        if result.returncode == 0:
            output = result.stdout
            # Assuming bolt.py outputs JSON formatted results to stdout
            try:
                data = json.loads(output)
                return data
            except json.JSONDecodeError:
                logging.error(f"Failed to parse JSON output from bolt.py for {subdomain}")
                return None
        else:
            logging.error(f"Running bolt.py for {subdomain} failed with error: {result.stderr}")
            return None
    except subprocess.CalledProcessError as e:
        logging.error(f"Running bolt.py for {subdomain} failed with error: {e}")
        return None
    finally:
        os.chdir(original_cwd)  # Ensure we return to the original directory even if an error occurs

def execute_clickjack():
    logging.info("Execution started")
    vuln=False
    d = open("wayback_urls.txt", 'r')
    hdr = {'User-Agent': 'Mozilla/5.0'}
    try:
        for target in d.readlines():
            
            t = target.strip('\n')
            if (("http") or ("https")) not in t:
                t = "https://"+t  
            try:
                req = Request(t, headers=hdr)
                data = urlopen(req, timeout=10)
                filename = urlparse(t).netloc
                headers = data.info()
                if not (("X-Frame-Options") or ("x-frame-options")) in headers:
                    vuln = True
                    print(colored(f"Target: {t} is Vulnerable", "green"))
                    print(colored(f"Generating {filename}.html POC File", "yellow"))
                    poc = """
                        <html>
                        <head><title>Clickjack POC page</title></head>
                        <body>
                        <p>Website is vulnerable to clickjacking!</p>
                        <iframe src="{}" width="500" height="500"></iframe>
                        </body>
                        </html>
                        """.format(t)
                    if ":" in filename:
                        url = filename.split(':')
                        filename=url[0]              
                    with open(filename+".html", "w") as pf:
                        pf.write(poc)
                    print(colored(f"Clickjacking POC file Created SuccessFully, Open {filename}.html to get the POC", "blue"))
                else:
                    vuln == False
                    print(colored(f"Target: {t} is not Vulnerable", "red"))
                    print("Testing Other Url's in the List")
            except KeyboardInterrupt as k:
                print("No Worries , I'm here to handle your KeyBoard Interrupts \n")
            except urllib.error.URLError as e:
                # handling HTTP 403 Forbidden timeout...
                print(f"Target {t} has some HTTP Errors via http:// lets let https:// ", exception)
            except requests.HTTPError as exception:
                print(f"Target {t} has some HTTP Errors :--> ", exception)
            except Exception as e:
                print("Exception Occured with Description ----> ", e)
                raise("Target Didn't Responsed")
        print("All Targets Tested Successfully !!")
    except exception as e:
        print(e)
        print("[*] Usage: python3 clickJackPoc.py -f <file_name>")
        print("[*] The Code might not worked for you , please retry & try --help option to know more")
        exit(0)

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
                print("Testing: "+ payloads[count])
                time.sleep(random.randint(1, 3))
                count += 1
                if "root:x:0:0:root" in browser.page_source:
                    vulnerable_urls.append(target_url)
                    print("Vuln Url: " +target_url)
                if count == len(payloads):
                    browser.close()
        except:
            raise 

    browser.quit()
    return vulnerable_urls


@app.route('/api/lfiFinder', methods=['POST'])
def run_LFI_Finder():
    with open("wayback_urls.txt", "r") as f:
        urls = f.readlines()
        for url in urls:
            url=str(url).strip()
            if url == "":
                continue
            elif url[-1] == '/' or url[-1] == '\\':
                url=url[:-1]
            print("Checking Vulnerablities for the url: "+url)
            vulnarablities=check_lfi_vulnerability(url)
            print("Vulnerable urls are: ")
            for v in vulnarablities:
                print(v)
    return "Thank you"

@app.route('/api/clickjack', methods=['POST'])
def run_clickjack():
    execute_clickjack()
    return "Thank you"

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
    #paramspider_data = asyncio.run(fetch_paramspider_urls_async(validated_subdomains))
    #save_data_to_file(domain, paramspider_data, 'paramspider_urls.json')
    #process_paramspider_results()
    #aggregate_dalfox_results()

    # Run bolt.py for each subdomain with status code 200
    bolt_results = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] == '200':
            bolt_result = run_bolt(subdomain['subdomain'])
            if bolt_result:
                bolt_results[subdomain['subdomain']] = bolt_result

    save_data_to_file(domain, bolt_results, 'bolt_results.json')

    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        'wayback_urls': wayback_data,
        #'paramspider_urls': paramspider_data,
        'bolt_results': bolt_results,
        'message': 'Scanning and aggregation completed'
    })

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')
