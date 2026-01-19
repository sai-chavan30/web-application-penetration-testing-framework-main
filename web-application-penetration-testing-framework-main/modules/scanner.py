# modules/scanner.py
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import pymysql

# Connect to DB (same config as app.py)
conn = pymysql.connect(host='localhost', user='admin', password='AdminPassword' , database='pentest_framework')
cursor = conn.cursor()

# SQLi and XSS payloads
SQLI_PAYLOADS = ["' OR '1'='1", "'--", "\" OR \"1\"=\"1"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

# Error patterns for SQLi detection
SQL_ERRORS = ["you have an error in your sql syntax", "unclosed quotation mark", "sql error", "mysql_fetch"]


def get_forms(url):
    soup = BeautifulSoup(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        type_ = input_tag.attrs.get("type", "text")
        inputs.append({"name": name, "type": type_})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = value
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)


def is_vulnerable_to_sqli(response):
    for error in SQL_ERRORS:
        if error in response.text.lower():
            return True
    return False


def scan_for_sql_injection(target_id, url):
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in SQLI_PAYLOADS:
            response = submit_form(details, url, payload)
            if is_vulnerable_to_sqli(response):
                cursor.execute("""
                    INSERT INTO vulnerabilities (target_id, vuln_type, payload, affected_url, severity, description, recommended_fix)
                    VALUES (%s, 'SQL Injection', %s, %s, 'High', 'Form vulnerable to SQL injection.', 'Use prepared statements and sanitize input.')
                """, (target_id, payload, url))
                conn.commit()
                break  # One payload match is enough


def scan_for_xss(target_id, url):
    forms = get_forms(url)
    for form in forms:
        details = form_details(form)
        for payload in XSS_PAYLOADS:
            response = submit_form(details, url, payload)
            if payload in response.text:
                cursor.execute("""
                    INSERT INTO vulnerabilities (target_id, vuln_type, payload, affected_url, severity, description, recommended_fix)
                    VALUES (%s, 'XSS', %s, %s, 'Medium', 'Form reflects payload without sanitization.', 'Escape output and use CSP headers.')
                """, (target_id, payload, url))
                conn.commit()
                break


def run_all_scans(target_id, url):
    try:
        scan_for_sql_injection(target_id, url)
        scan_for_xss(target_id, url)
        print(f"Scan completed for {url}")
    except Exception as e:
        print(f"Error scanning {url}: {e}")
