import subprocess
import json
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/api/subdomains', methods=['POST'])
def get_subdomains():
    domain = request.json.get('domain')
    attacker_ip = request.json.get('attacker_ip')
    attacker_port = request.json.get('attacker_port')
    attacker_server_port = request.json.get('attacker_server_port')
    wayback_data = request.json.get('wayback_data')

    rfi_results = {}
    for subdomain, urls in wayback_data.items():
        for url in urls:
            url_rfi_results = run_rfi_docker(url, attacker_ip, attacker_port, attacker_server_port)
            if url_rfi_results:
                rfi_results[url] = url_rfi_results

    save_rfi_results_to_file(domain, rfi_results, 'rfi_results.json')

    return jsonify({
        'rfi_results': rfi_results
    })

def run_rfi_docker(url, attacker_ip, attacker_port, attacker_server_port):
    try:
        output = subprocess.check_output([
            'docker', 'run', '--rm', 'rfi_check_image',
            url, attacker_ip, str(attacker_port), str(attacker_server_port)
        ])
        return output.decode('utf-8')
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def save_rfi_results_to_file(domain, results, filename):
    output_dir = os.path.join('rfi_scan_results', domain)
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, filename), 'w') as f:
        json.dump(results, f, indent=4)

if __name__ == '__main__':
    app.run(debug=True)
