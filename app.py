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
    
    with open(aggregate_file_path, 'w') as aggregate_file:
        for filename in os.listdir(dalfox_results_dir):
            if filename.startswith('dalfox_') and filename.endswith('.txt'):
                file_path = os.path.join(dalfox_results_dir, filename)
                with open(file_path, 'r') as file:
                    results = file.read()
                    if results.strip():  # Only write if there's content
                        aggregate_file.write(f"Results from {filename}:\n{results}\n\n")


def run_bolt(subdomain):
    bolt_data = {}
    if subdomain['status_code'] == '200':
        bolt_dir = 'Bolt'
        if os.path.isdir(bolt_dir):
            os.chdir(bolt_dir)
            try:
                result = subprocess.run(
                    ['python3', 'bolt.py', '-u', subdomain['subdomain'], '-l', '2'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                bolt_data[subdomain['subdomain']] = result.stdout
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to run Bolt for {subdomain['subdomain']}: {e.stderr}")
            except FileNotFoundError as e:
                logging.error(f"File not found: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")
            finally:
                os.chdir('..')
        else:
            logging.error(f"Bolt directory '{bolt_dir}' does not exist")
    return bolt_data

def run_see_surf(subdomain):
    see_surf_data = {}
    if subdomain['status_code'] == '200':
        see_surf_dir = 'See-SURF'
        if os.path.isdir(see_surf_dir):
            os.chdir(see_surf_dir)
            try:
                result = subprocess.run(
                    subd = subdomain['subdomain']
                    ['python3', 'see-surf.py', '-H', 'subd'],
                    capture_output=True,
                    text=True,
                    check=True
                )
                see_surf_data[subdomain['subdomain']] = result.stdout
            except subprocess.CalledProcessError as e:
                logging.error(f"Failed to run See-SURF for {subdomain['subdomain']}: {e.stderr}")
            except FileNotFoundError as e:
                logging.error(f"File not found: {e}")
            except Exception as e:
                logging.error(f"An unexpected error occurred: {e}")
            finally:
                os.chdir('..')
        else:
            logging.error(f"See-SURF directory '{see_surf_dir}' does not exist")
    return see_surf_data


def process_bolt_and_see_surf(validated_subdomains):
    bolt_results = {}
    see_surf_results = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] == '200':
            bolt_output = run_bolt(subdomain)
            if bolt_output:
                bolt_results.update(bolt_output)
            see_surf_output = run_see_surf(subdomain)
            if see_surf_output:
                see_surf_results.update(see_surf_output)
    return bolt_results, see_surf_results

def execute_clickjack():
    logging.info("Execution started")
    hdr = {'User-Agent': 'Mozilla/5.0'}
    results = []

    with open("wayback_urls.txt", 'r') as d:
        try:
            for target in d.readlines():
                t = target.strip('\n')
                if not t.startswith(("http://", "https://")):
                    t = "https://" + t

                try:
                    req = Request(t, headers=hdr)
                    data = urlopen(req, timeout=10)
                    headers = data.info()

                    if "X-Frame-Options" not in headers and "x-frame-options" not in headers:
                        print(colored(f"Target: {t} is Vulnerable", "green"))
                        filename = urlparse(t).netloc
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
    
    with open("vulnerability_results.json", "w") as json_file:
        json.dump(results, json_file, indent=4)
        print("Results written to vulnerability_results.json")

        

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

def run_LFI_Finder():
    with open("paramspider_urls.txt", "r") as f:
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
    #process_paramspider_results()
    #aggregate_dalfox_results()
    execute_clickjack()
    #run_LFI_Finder()
    #bolt_results, see_surf_results = process_bolt_and_see_surf(validated_subdomains)
    #save_data_to_file(domain, bolt_results, 'bolt_results.json')
    #save_data_to_file(domain, see_surf_results, 'see_surf_results.json')

    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        #'wayback_urls': wayback_data,
        #'paramspider_urls': paramspider_data,
        #'aggregation': 'Scanning and aggregation completed',
        #'bolt_results': bolt_results,
        #'see_surf_results': see_surf_results,
    })
    



if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')
