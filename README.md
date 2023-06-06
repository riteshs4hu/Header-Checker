<h1 align=center>Security Headers Checker Python Script.</h1>

<p align="center">
  <a href="#description">Description</a> •
  <a href="#prerequisites">Prerequisites</a> •
  <a href="#installation">Installation</a> •
  <a href="#examples">Examples</a>
</p>

## Description

This script is used to check the presence of security headers in web pages. It takes either a single URL or a file containing a list of URLs as input and checks for the presence or absence of specific security headers.

### Arguments

- `-u URL, --url URL`: The URL or domain to check.
- `-m METHOD, --method METHOD`: The HTTP request method to use (default: GET).
- `-l FILE, --list FILE`: File containing a list of URLs or domains.
- `-o FILE, --output FILE`: Output file path.
- `-j, --json`: JSON output format.

## Prerequisites

The script requires the following dependencies:

- argparse
- requests
- json
- concurrent.futures
- sys

## Installation

```
git clone https://github.com/Mr-Secure-Code/Header-Checker.git &&
cd Header-Checker
chmod +x header-checker.py
./header-checker.py
```

## Examples

-   To check a single URL:

    ```
    python header-checker.py -u https://example.com
    ```

-   To check a list of URLs from a file:

    ```
    python header-checker.py -l urls.txt
    ```

-   To check a single URL and save output:

    ```
    python header-checker.py -u https://example.com -o output.txt
    ```

-   To check a single URL and save json output:

    ```
    python header-checker.py -u https://example.com -j -o output.json
    ```
