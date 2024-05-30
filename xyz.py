import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectionError

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
        print(f"Failed to establish a connection for URL: {url}")
        return None
    except Exception as e:
        print(f"An error occurred while fetching CSRF token for URL {url}: {e}")
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

# List of URLs to check for CSRF vulnerability
urls = [
    "http://testphp.vulnweb.com:80/.idea/vcs.xml",
    "http://testphp.vulnweb.com:80/.idea/workspace.xml",
    "http://testphp.vulnweb.com/.well-known/ai-plugin.json",
]

# Iterate over each URL and check for CSRF vulnerability
for url in urls:
    print("Checking CSRF vulnerability for:", url)
    csrf_token = get_csrf_token(url)
    if csrf_token:
        if check_csrf_vulnerability(url, csrf_token):
            print("CSRF vulnerability found at:", url)
        else:
            print("No CSRF vulnerability found at:", url)
    else:
        print("CSRF token not found for URL:", url)