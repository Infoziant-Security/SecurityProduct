import re
from flask import Flask, jsonify, request
from flask_cors import CORS
import subprocess
import json
import os

app = Flask(__name__)
CORS(app)

def find_subdomains_assetfinder(domain):
    subdomains = set()
    try:
        result = subprocess.run(['assetfinder', domain], capture_output=True, text=True)
        output = result.stdout
        lines = output.split('\n')
        for line in lines:
            subdomain = line.strip()
            if subdomain.endswith(domain):
                subdomains.add(subdomain)
        return subdomains
    except Exception as e:
        print(f"Error running Assetfinder: {e}")
        return set()

def find_subdomains_subfinder(domain):
    subdomains = set()
    try:
        result = subprocess.run(['subfinder', '-d', domain], capture_output=True, text=True)
        output = result.stdout
        lines = output.split('\n')
        for line in lines:
            subdomain = line.strip()
            if subdomain.endswith(domain):
                subdomains.add(subdomain)
        return subdomains
    except Exception as e:
        print(f"Error running Subfinder: {e}")
        return set()

def find_subdomains(domain):
    subdomains_assetfinder = find_subdomains_assetfinder(domain)
    subdomains_subfinder = find_subdomains_subfinder(domain)
    return list(subdomains_assetfinder.union(subdomains_subfinder))

def strip_ansi_codes(text):
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def validate_subdomains(subdomains):
    with open('subdomains.txt', 'w') as f:
        f.write('\n'.join(f'http://{sub}' for sub in subdomains))

    result = subprocess.run(['httpx', '-status-code', '-l', 'subdomains.txt'], capture_output=True, text=True)
    validated_subdomains = []
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
            try:
                result = subprocess.run(['waybackurls', subdomain['subdomain']], capture_output=True, text=True)
                urls = result.stdout.splitlines()
                wayback_data[subdomain['subdomain']] = urls
            except Exception as e:
                print(f"Error running waybackurls for {subdomain['subdomain']}: {e}")
    return wayback_data

def save_data_to_file(domain, data, filename):
    if os.path.exists(filename):
        with open(filename, 'r+') as file:
            try:
                existing_data = json.load(file)
            except json.JSONDecodeError:
                existing_data = {}
            existing_data[domain] = data
            file.seek(0)
            json.dump(existing_data, file, indent=4)
            file.truncate()
    else:
        with open(filename, 'w') as file:
            json.dump({domain: data}, file, indent=4)

@app.route('/subdomains', methods=['POST'])
def get_subdomains():
    domain = request.json.get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400

    subdomains = find_subdomains(domain)
    validated_subdomains = validate_subdomains(subdomains)
    wayback_data = fetch_wayback_urls(validated_subdomains)
    save_data_to_file(domain, validated_subdomains, 'validated_subdomains.json')
    save_data_to_file(domain, wayback_data, 'wayback_urls.json')

    return jsonify({
        'domain': domain,
        'validated_subdomains': validated_subdomains,
        'wayback_urls': wayback_data
    })

if __name__ == '__main__':
    app.run(debug=True)
