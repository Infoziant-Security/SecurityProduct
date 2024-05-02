from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import json

app = Flask(__name__)
CORS(app)

# Path to the JSON file that will store the data
DATA_FILE = 'urls_data.json'

def read_data():
    try:
        with open(DATA_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []

def write_data(data):
    with open(DATA_FILE, 'w') as file:
        json.dump(data, file, indent=4)

@app.route('/api/fetch', methods=['POST'])
def fetch_urls():
    data = request.json
    url = data['url']
    
    try:
        result = subprocess.run(['waybackurls', url], capture_output=True, text=True, encoding='utf-8')
        urls = result.stdout.splitlines()
        
        # Read existing data
        existing_data = read_data()
        # Append new data
        existing_data.append({"url": url, "waybackurls": urls})
        # Write back to the file
        write_data(existing_data)
        
        return jsonify({"url": url, "waybackurls": urls})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/urls', methods=['GET'])
def get_urls():
    return jsonify(read_data())

if __name__ == '__main__':
    app.run(debug=True)
