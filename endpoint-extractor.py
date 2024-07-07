import argparse
import re
import os

def extract_endpoints_and_sensitive_data(filename, args):
    try:
        with open(filename, 'r') as file:
            content = file.read()

        # Define regex patterns
        endpoint_pattern = re.compile(r'https?://[^\s\'"<>]+|/[^\s\'"<>]+')
        sensitive_data_patterns = {
            'Password': re.compile(r'password\s*[:=]\s*["\']?[^"\'\s]+["\']?', re.IGNORECASE),
            'Email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
            'Authorization Token': re.compile(r'authorization\s*[:=]\s*["\']?[^"\']+', re.IGNORECASE),
            'Authentication Token': re.compile(r'authentication\s*[:=]\s*["\']?[^"\']+', re.IGNORECASE),
            'API Key': re.compile(r'api[_-]?key\s*[:=]\s*["\']?[^"\']+', re.IGNORECASE),
        }

        # Extract endpoints
        endpoints = endpoint_pattern.findall(content)
        
        # Check for sensitive data
        sensitive_data_found = []
        for label, pattern in sensitive_data_patterns.items():
            if pattern.findall(content):
                sensitive_data_found.append(label)
        
        # Display endpoints in green color
        print("\033[92m" + "Endpoints found:" + "\033[0m")
        for endpoint in endpoints:
            print("\033[92m" + endpoint + "\033[0m")
        
        if sensitive_data_found:
            print("\033[91m" + "Sensitive data found: " + ", ".join(sensitive_data_found) + "\033[0m")
        else:
            print("No sensitive data found.")

        # Check for DOM-based XSS vulnerabilities if --dom-xss flag is set
        if args.dom_xss:
            detect_dom_based_xss(content)

    except FileNotFoundError:
        print(f"File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def detect_dom_based_xss(content):
    try:
        # Define regex pattern for potential XSS payloads
        xss_payload_pattern = re.compile(r'<script[^>]*>[\s\S]*?</script>|<img[^>]+(onerror|onload)\s*=\s*"[^"]+"|document\.location\s*=\s*["\'][^"\']+["\']')

        # Search for potential XSS payloads
        matches = xss_payload_pattern.findall(content)

        # Display findings
        if matches:
            print("\033[91m" + "Potential DOM-based XSS vulnerabilities found:" + "\033[0m")
            for match in matches:
                print("\033[91m" + match + "\033[0m")
        else:
            print("No potential DOM-based XSS vulnerabilities found.")

    except Exception as e:
        print(f"An error occurred during DOM-based XSS detection: {e}")

def main():
    parser = argparse.ArgumentParser(description="Tool to extract endpoints, check for sensitive data, and detect DOM-based XSS vulnerabilities in a file.")
    parser.add_argument('-o', '--output', metavar='OUTPUT_PATH', type=str, help='Specify output location for results.')
    parser.add_argument('-t', '--file', metavar='FILE_PATH', type=str, help='Specify the file to analyze.')
    parser.add_argument('--dom-xss', action='store_true', help='Enable DOM-based XSS detection.')
    args = parser.parse_args()

    if not args.file:
        parser.print_help()
        return

    filename = args.file
    extract_endpoints_and_sensitive_data(filename, args)

    if args.output:
        output_path = os.path.abspath(args.output)
        print(f"Results saved to: {output_path}")

if __name__ == "__main__":
    main()
