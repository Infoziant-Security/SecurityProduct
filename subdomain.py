import re
import subprocess
import json
import os
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from logging.config import dictConfig
import asyncio


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

def run_dalfox_scan(url):
    command = ['dalfox', 'url', url]
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8')
        return result.stdout
    except subprocess.CalledProcessError as e:
        logging.error(f"Dalfox scanning failed for {url} with error {e}")
        return None

    
def extract_xss_vulnerable_urls(dalfox_output):
    vulnerable_urls = []
    lines = dalfox_output.split('\n')
    for line in lines:
        if '[POC]' in line:
            start = line.find('http')
            if start != -1:
                end = line.find(' ', start)
                if end == -1:
                    end = len(line)
                vulnerable_url = line[start:end]
                vulnerable_urls.append(vulnerable_url)
    return vulnerable_urls

def update_json_file(domain, data, filename):
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

@app.route('/api/subdomains', methods=['POST'])
def get_subdomains():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    subdomains_assetfinder = find_subdomains(domain, 'assetfinder')
    subdomains_subfinder = find_subdomains(domain, 'subfinder')
    subdomains = list(subdomains_assetfinder.union(subdomains_subfinder))
    validated_subdomains = validate_subdomains(subdomains)
    wayback_data = fetch_wayback_urls(validated_subdomains)
    paramspider_data = asyncio.run(fetch_paramspider_urls_async(validated_subdomains))
    xss_vulnerable_urls = []
    for url in paramspider_data.values():
        for u in url:
            dalfox_output = run_dalfox_scan(u)
            if dalfox_output:
                xss_urls = extract_xss_vulnerable_urls(dalfox_output)
                xss_vulnerable_urls.extend(xss_urls)

    save_data_to_file(domain, validated_subdomains, 'validated_subdomains.json')
    save_data_to_file(domain, wayback_data, 'wayback_urls.json')
    save_data_to_file(domain, paramspider_data, 'paramspider_urls.json')
    save_data_to_file(domain, xss_vulnerable_urls, 'xss_vulnerable_urls.json')

    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        'wayback_urls': wayback_data,
        'paramspider_urls': paramspider_data,
        'xss_vulnerable_urls': xss_vulnerable_urls
    })

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')
