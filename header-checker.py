import argparse
import requests
import json
import concurrent.futures
import sys

# List of security headers to check
sec_headers = [
    'X-XSS-Protection',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Permitted-Cross-Domain-Policies',
    'Referrer-Policy',
    'Expect-CT',
    'Permissions-Policy',
    'Cross-Origin-Embedder-Policy',
    'Cross-Origin-Resource-Policy',
    'Cross-Origin-Opener-Policy',
    'X-Cache',
    'X-Amz-Cf-Pop',
    'Cache-Control'
]

# ANSI escape codes for color formatting
COLOR_HEADER = "\033[95m"
COLOR_FOUND = "\033[92m"
COLOR_MISSING = "\033[91m"
COLOR_END = "\033[0m"

def print_banner():
    banner = '''
        \033[1;36m _                    _                  _               _              
        \033[1;36m| |                  | |                | |             | |             
        \033[1;36m| |__   ___  __ _  __| | ___ _ __    ___| |__   ___  ___| | _____ _ __  
        \033[1;36m| '_ \ / _ \/ _` |/ _` |/ _ \ '__|  / __| '_ \ / _ \/ __| |/ / _ \ '__| 
        \033[1;36m| | | |  __/ (_| | (_| |  __/ |    | (__| | | |  __/ (__|   <  __/ |    
        \033[1;36m|_| |_|\___|\__,_|\__,_|\___|_|     \___|_| |_|\___|\___|_|\_\___|_|    
        \033[1;33m------------------------------------------------------------------------\033[0m
        \033[0;31m[\033[0m\033[1;36m+\033[0m\033[0;31m]\033[0m \033[1;34mhttps://github.com/Mr-Secure-Code/\033[0m
        \033[0;31m[\033[0m\033[1;36m+\033[0m\033[0;31m]\033[0m \033[0m\033[1;32mCheck Security Headers\033[0m
        \033[1;33m------------------------------------------------------------------------\033[0m
                                                \033[0;31mby Ritesh Sahu\033[0m
    '''
    print(banner)

def check_response_headers(url, method):
    try:
        response = requests.request(method, url)
    except requests.exceptions.RequestException as e:
        print(f"An error occurred while accessing {url}: {str(e)}")
        return None

    headers_found = []
    headers_missing = []

    for sec_header in sec_headers:
        if sec_header in response.headers:
            headers_found.append(sec_header)
        else:
            headers_missing.append(sec_header)

    return {
        "url": url,
        "method": method,
        "headers_found": headers_found,
        "headers_missing": headers_missing
    }


def read_url_list(file_path):
    with open(file_path, "r") as file:
        urls = file.read().splitlines()
    return urls

def save_output(output, output_file):
    if output_file:
        with open(output_file, "a") as file:
            file.write(output)
            file.write("\n")
    print(output)  # Always print the output on the console

def analyze_url(url, method):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # Prepend http:// if missing

    return check_response_headers(url, method)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", dest="url", metavar="URL", help="URL or domain")
    parser.add_argument("-m", "--method", dest="method", metavar="METHOD", default="GET",
                        help="HTTP request method (default: GET)")
    parser.add_argument("-l", "--list", dest="list_file", metavar="FILE", help="File containing a list of URLs or domains")
    parser.add_argument("-o", "--output", dest="output_file", metavar="FILE", help="Output file path")
    parser.add_argument("-j", "--json", dest="output_format", action="store_const", const="json", default="console",
                        help="JSON output format")
    args = parser.parse_args()

    if args.url and args.list_file:
        parser.error("Please provide either a single URL or a list file, not both.")

    method = args.method.upper()

    if args.url:
        url = args.url

        result = analyze_url(url, method)

        if result is None:
            print(f"Unable to access {url}")
        else:
            if args.output_format == "json":
                output = json.dumps(result, indent=4)
            else:
                output = ""
                output += COLOR_HEADER + "Security Headers:" + COLOR_END + "\n"
                safe = len(result["headers_found"])
                for sec_header in sec_headers:
                    if sec_header in result["headers_found"]:
                        output += f"{sec_header}: {COLOR_FOUND}Found{COLOR_END}\n"
                    else:
                        output += f"{sec_header}: {COLOR_MISSING}Missing{COLOR_END}\n"

                output += "-------------------------------------------------------\n"
                output += "Headers analyzed for {}\n".format(url)
                output += "There are {} security headers\n".format(safe)
                output += "There are not {} security headers\n".format(len(sec_headers) - safe)
                output += COLOR_HEADER + "HTTP Request Method: {}".format(method) + COLOR_END

            save_output(output, args.output_file)
    elif args.list_file:
        urls = read_url_list(args.list_file)

        with concurrent.futures.ThreadPoolExecutor() as executor:
            results = []
            for url in urls:
                results.append(executor.submit(analyze_url, url, method))

            for future, url in zip(concurrent.futures.as_completed(results), urls):
                result = future.result()

                if result is None:
                    print(f"Unable to access {url}")
                else:
                    if args.output_format == "json":
                        output = json.dumps(result, indent=4)
                    else:
                        output = ""
                        output += COLOR_HEADER + "Security Headers:" + COLOR_END + "\n"
                        safe = len(result["headers_found"])
                        for sec_header in sec_headers:
                            if sec_header in result["headers_found"]:
                                output += f"{sec_header}: {COLOR_FOUND}Found{COLOR_END}\n"
                            else:
                                output += f"{sec_header}: {COLOR_MISSING}Missing{COLOR_END}\n"

                        output += "-------------------------------------------------------\n"
                        output += "Headers analyzed for {}\n".format(result["url"])
                        output += "There are {} security headers\n".format(safe)
                        output += "There are not {} security headers\n".format(len(sec_headers) - safe)
                        output += COLOR_HEADER + "HTTP Request Method: {}".format(result["method"]) + COLOR_END

                    save_output(output, args.output_file)
                    print()  # Add an empty line between each URL

if __name__ == "__main__":
    if len(sys.argv) == 1:
        print_banner()
    main()

