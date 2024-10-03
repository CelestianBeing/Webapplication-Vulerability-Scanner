import requests
from bs4 import BeautifulSoup

# Set up vulnerable payloads for basic SQL Injection, XSS, CSRF checks
vulnerable_payloads = {
    "sqli": "' OR '1'='1",
    "xss": "<script>alert('XSS')</script>",
    "csrf": "<form action='/vulnerable-endpoint' method='POST'><input type='hidden' name='csrf_token' value='fake'></form>"
}

def check_sql_injection(url):
    print(f"Checking for SQL Injection in {url}")
    vulnerable_url = f"{url}?id={vulnerable_payloads['sqli']}"
    response = requests.get(vulnerable_url)
    if "syntax error" in response.text or "sql" in response.text.lower():
        print(f"Possible SQL Injection vulnerability detected at {url}")
    else:
        print(f"No SQL Injection vulnerability detected at {url}")

def check_xss(url):
    print(f"Checking for XSS in {url}")
    params = {'q': vulnerable_payloads['xss']}
    response = requests.get(url, params=params)
    if vulnerable_payloads['xss'] in response.text:
        print(f"Possible XSS vulnerability detected at {url}")
    else:
        print(f"No XSS vulnerability detected at {url}")

def check_csrf(url):
    print(f"Checking for CSRF in {url}")
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    forms = soup.find_all('form')
    if forms:
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                print(f"Possible CSRF vulnerability detected in form at {url}")
            else:
                print(f"No CSRF vulnerability detected at {url}")

def run_scanner(url):
    check_sql_injection(url)
    check_xss(url)
    check_csrf(url)

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    run_scanner(target_url)
