from CORScanner.cors_scan import cors_check
import re
import subprocess
import json
import os
import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from logging.config import dictConfig
import httpx

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
        return subprocess.run(command, capture_output=True, text=True, check=True)
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

def validate_wayback_urls(wayback_urls):
    validated_wayback_urls = {}
    f = open("wayback_urls.txt", "r")
    data=f.read()
    wayback_data= data.split("\n")
    for u in wayback_data:
        r = httpx.get(u)
        app.logger.info(f'{u}-{r}')
        validated_wayback_urls[u]=r.status_code
    
    return validated_wayback_urls

def fetch_wayback_urls(validated_subdomains):
    wayback_data = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] == '200':
            result = run_subprocess(['waybackurls', subdomain['subdomain']])
            if result:
                urls = result.stdout.splitlines()
                wayback_data[subdomain['subdomain']] = urls
    return wayback_data

def fetch_paramspider_urls(validated_subdomains):
    paramspider_data = {}
    for subdomain in validated_subdomains:
        if subdomain['status_code'] == '200':
            domain_name = subdomain['subdomain'].split("//")[-1]
            result = run_subprocess(['paramspider', '-d', domain_name])
            if result:
                output_file_path = f"results/{domain_name}.txt"
                if os.path.exists(output_file_path):
                    with open(output_file_path, 'r') as file:
                        urls = file.readlines()
                    paramspider_data[subdomain['subdomain']] = [url.strip() for url in urls]
                else:
                    logging.error(f"Expected output file not found: {output_file_path}")
            else:
                logging.error(f"ParamSpider failed for {subdomain['subdomain']}")
    return paramspider_data


def save_data_to_file(domain, data, filename):
    path = os.path.join(os.getenv('DATA_DIR', './'), filename)
    with open(path, 'a+') as file:
        file.seek(0)
        try:
            existing_data = json.load(file)
        except json.JSONDecodeError:
            existing_data = {}
        existing_data[domain] = data
        file.seek(0)
        json.dump(existing_data, file, indent=4)
        file.truncate()

def find_403_from_wayback(wayback_dict):
    wayback_403={}
    for u in wayback_dict:
        if('403' in str(wayback_dict[u])):
            result=subprocess.run(['bypass-403.sh',u],shell=True, stdout=subprocess.PIPE)
            wayback_403[u]=str(result)
    app.logger.info(wayback_403)
    return wayback_403

def read_wayback_urls(filename):
    f = open(filename)
    wayback_data=json.load(f)
    f.close()
    return wayback_data

def execute_cors_scaner(filename):
    f = open(filename, "r")
    data=f.read()
    subdomain_list= data.split("\n")
    cors_result={}
    for u in subdomain_list:
        ret = subprocess.run(["cors","-u",u],stdout=subprocess.PIPE)
        # ret = cors_check(u, 0)
        cors_result[u]=str(ret)
        app.logger.info(ret)
    return cors_result

@app.route('/api/corsand403', methods=['GET', 'POST'])
def check_cors_and_403():
    #403 Bypass check
    # wayback_data=read_wayback_urls('wayback_urls.json')
    # app.logger.info("Wayback data extracted")
    # validated_wayback_urls=validate_wayback_urls(list(wayback_data.values()))
    # wayback_403_data = find_403_from_wayback(validated_wayback_urls)
    # app.logger.info("Wayback 403 Bypass check executed")
    #CORS Scanner
    cors_scanner_result=execute_cors_scaner('subdomains.txt')
    save_data_to_file('domain', cors_scanner_result, 'cors_scanner_result.json')
    return 'Wayback 403 Bypass check executed'



@app.route('/api/subdomains', methods=['GET', 'POST'])
def get_subdomains():
    domain = request.json.get('domain')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    subdomains_assetfinder = find_subdomains(domain, 'assetfinder')
    subdomains_subfinder = find_subdomains(domain, 'subfinder')
    subdomains = list(subdomains_assetfinder.union(subdomains_subfinder))
    validated_subdomains = validate_subdomains(subdomains)
    wayback_data = fetch_wayback_urls(validated_subdomains)
    paramspider_data = fetch_paramspider_urls(validated_subdomains)
    save_data_to_file(domain, validated_subdomains, 'validated_subdomains.json')
    save_data_to_file(domain, wayback_data, 'wayback_urls.json')
    save_data_to_file(domain, paramspider_data, 'paramspider_urls.json')

    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        'wayback_urls': wayback_data,
        'paramspider_urls': paramspider_data
    })

if __name__ == '__main__':
    app.run(debug=os.getenv('DEBUG', 'False') == 'True')
