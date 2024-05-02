from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_socketio import SocketIO
import subprocess
import dns.resolver
import asyncio
import aiohttp
import os
import json
from multiprocessing import Pool
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*") 

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
        return set()

def find_subdomains(domain):
    with Pool(2) as p:
        subdomains_assetfinder, subdomains_subfinder = p.starmap(find_subdomains_func, [(domain, 'assetfinder'), (domain, 'subfinder')])
    subdomains = subdomains_assetfinder.union(subdomains_subfinder)
    for subdomain in subdomains:
        socketio.emit('subdomain_found', {'subdomain': subdomain})
    return subdomains


def find_subdomains_func(domain, tool):
    if tool == 'assetfinder':
        return find_subdomains_assetfinder(domain)
    elif tool == 'subfinder':
        return find_subdomains_subfinder(domain)

async def resolve_dns(subdomain):
    try:
        return dns.resolver.resolve(subdomain, 'A')
    except Exception as e:
        return None

async def check_http_status(session, subdomain):
    url = f"http://{subdomain}"
    try:
        async with session.head(url, timeout=5) as response:
            return response.status
    except aiohttp.ClientError as e:
        return None
    except asyncio.TimeoutError:
        return None
    
async def validate_subdomains(subdomains):
    validated_subdomains = []
    async with aiohttp.ClientSession() as session:
        dns_tasks = [resolve_dns(subdomain) for subdomain in subdomains]
        resolved_results = await asyncio.gather(*dns_tasks)
        for subdomain, result in zip(subdomains, resolved_results):
            if result:
                http_status = await check_http_status(session, subdomain)
                if http_status:
                    validated_subdomain = {
                        'subdomain': subdomain,
                        'dns_resolved': True,
                        'http_status': http_status
                    }
                    validated_subdomains.append(validated_subdomain)
                    socketio.emit('subdomain_validated', validated_subdomain)
    return validated_subdomains

def save_subdomains_to_file(domain, subdomains):
    file_path = 'subdomains.json'
    data = {}

def validate_and_save_subdomains(domain, subdomains):
    validated_subdomains = asyncio.run(validate_subdomains(subdomains))
    save_subdomains_to_file(domain, validated_subdomains, 'validated_subdomains.json')

def save_subdomains_to_file(domain, subdomains, filename):
    file_path = filename
    data = {}

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            try:
                data = json.load(file)
            except json.JSONDecodeError:
                pass

    data[domain] = subdomains

    with open(file_path, 'w') as file:
        json.dump(data, file)

@app.route('/subdomains', methods=['POST'])
def get_subdomains():
    data = request.get_json()
    domain = data['domain']
    subdomains = find_subdomains(domain)
    save_subdomains_to_file(domain, list(subdomains), 'found_subdomains.json')

    executor = ThreadPoolExecutor(max_workers=1)
    executor.submit(validate_and_save_subdomains, domain, subdomains)

    return jsonify(list(subdomains))

if __name__ == '__main__':
    app.run(debug=True)
