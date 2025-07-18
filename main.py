from flask import Flask, request, jsonify , render_template, make_response
from flask_cors import CORS
import subprocess
import shutil  #  Import shutil to check if Nmap exists
import re  # Import regex module for filtering open ports
import requests  # ✅ Import requests to fetch headers
#kjdskjlsdfkl
#kjlggfiuoijghklkjlk.ddvsldvse
from data_base import init_db, get_db_session , CompanyInfo, Vulnerabilities, runExtraQueries, Vulnerable, VulnerableAIResponse 
import os
import json 
import subprocess
from urllib.parse import urljoin
from urllib.parse import urlparse, urlunparsesdn,sdsk,ks
import multiprocessing
import time
import os
from datetime import datetime, timezone
import socket
#fghjkkjhg
import random
from email_base import sendOtp
from bs4 import BeautifulSoup
import whois
import builtwith
import sys
import dns.resolver
import openai
import urllib.parse

from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter

import utilities

import pytz










app = Flask(__name__, template_folder="templates")
CORS(app, resources={r"/*": {"origins": "*"}})  # Allows frontend (PHP) to call API from another domain

# ✅ Initialize Database (Create Tables)
init_db()
runExtraQueries()

# ✅ Get a new session for database operations
session = get_db_session()


@app.route("/")
def home():
    return render_template("index.html")  # Serve the HTML page

# def is_domain_live(domain):
#     """
#     ✅ Checks if a domain is live using curl.
#     ✅ Returns True if reachable, else False.
#     """
#     try:
#         result = subprocess.run(
#             ["curl", "-I", domain],
#             capture_output=True, text=True, timeout=200
#         )
#         if "HTTP/" in result.stdout:  # ✅ Found valid HTTP response
#             return True
#     except subprocess.TimeoutExpired:
#         pass  # Ignore timeout errors
#     except Exception as e:
#         print(f"Error checking {domain}: {e}")

#     return False  # ❌ Not live

# ✅ Directory for storing JSON results
SCAN_RESULTS_DIR = "scan_results"

# ✅ Ensure directory exists
if not os.path.exists(SCAN_RESULTS_DIR):
    os.makedirs(SCAN_RESULTS_DIR)
    # ✅ Ensure the directory exists
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
def save_scan_result(temp_id, scan_data):
    """ ✅ Save scan data to a JSON file (creates if not exists) using temp_id """


    file_path = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")
    temp_path = file_path + ".tmp"

    try:
        # ✅ If the file exists, load existing data
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                try:
                    existing_data = json.load(file)
                except json.JSONDecodeError:
                    print(f"⚠️ Warning: Corrupted existing file for {temp_id}. Starting fresh.")
                    existing_data = {}
        else:
            existing_data = {}  # ✅ Create new JSON structure

        # ✅ Update with new scan data
        # Set timezone to Asia/Kolkata
        india_tz = pytz.timezone('Asia/Kolkata')
        now_in_india = datetime.now(india_tz)
        # Format scan end time
        scan_data["scan_end_time"] = now_in_india.strftime("%B %d, %Y at %I:%M %p").lstrip("0").replace(" 0", " ") # Remove leading zero and replace " 0" with " "
        existing_data.update(scan_data)  

        # ✅ Write updated JSON file
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(existing_data, file, indent=4)

        # Replace the old file with the new file atomically
        os.replace(temp_path, file_path)

        # ✅ Print JSON response correctly
        print("✅ Scan results (JSON format):")
        print(json.dumps(existing_data, indent=4))  # Correct print format

    except json.JSONDecodeError:
        print(f"❌ Error reading JSON file (possibly corrupted): {file_path}")
    except Exception as e:
        print(f"❌ Error saving scan result for temp_id {temp_id}: {e}")




def resolve_live_url(domain, timeout=10):
    """
    Attempts to resolve the given domain to a live URL by checking HTTPS and HTTP schemes.
    Returns the live URL if successful, or None if both fail.
    """

    # Extract base domain if input is a full URL
    parsed = urlparse(domain)

    def normalize_to_root(url):
        parsed = urlparse(url)
        return urlunparse((parsed.scheme, parsed.netloc, "/", '', '', ''))
    # domain = parsed.netloc if parsed.netloc else parsed.path  # Handles cases like just 'example.com'

    if "google.com" in domain:
        return "https://www.google.com/"

    # If the domain already includes a scheme, test it directly
    if domain.startswith(('http://', 'https://')):
        try:
            response = requests.get(
            domain,
            timeout=timeout,
            allow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "DNT": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
            }
        )
            if response.status_code < 409:
                return normalize_to_root(response.url)  # Return the resolved URL
        except requests.RequestException:
            return None
    else:
        # Try HTTPS first, then HTTP
        for scheme in ['https://', 'http://']:
            test_url = f"{scheme}{domain}"
            try:
                response = requests.get(
                test_url,
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Accept-Encoding": "gzip, deflate, br",
                    "Connection": "keep-alive",
                    "Upgrade-Insecure-Requests": "1",
                    "DNT": "1",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Site": "none",
                    "Sec-Fetch-User": "?1",
                }
            )
                if response.status_code < 409:
                    return normalize_to_root(response.url)
            except requests.RequestException:
                continue
    return None





def get_whois_info(domain, entry_id):
    session = get_db_session()
     # Extract domain name if URL includes scheme
    parsed_url = urlparse(domain)
    domain_name = parsed_url.netloc or parsed_url.path  # Handles cases with or without scheme
 


    # :magnifying_glass: Get company_id from entry_id
    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    
    company_id = company.id
    print("whois domain name")
    print(domain_name)
    MAX_RETRIES = 3
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            print(f"getting the wso_is information ")
            print(whois.__file__)
            whois_info = whois.whois(domain_name)
            
            whois_info = json.dumps(whois_info, default=custom_serializer, indent=2)
            print("whois returned")
            # print(whois_info)
            session.query(Vulnerabilities).filter(Vulnerabilities.company_id == company_id).update(
            {"info_http_headers": whois_info}
            )
            session.commit()
            # :white_tick: Save in JSON file
            save_scan_result(entry_id, {"whois_info": whois_info})
            print(f"✅ WHOIS info saved for {domain_name}")
            # update_scan_completion_status(entry_id=entry_id)
            return whois_info
        
        except Exception as e:
            print(f"Error retrieving WHOIS info: {e}")
            time.sleep(2)  # Wait before retrying

            if attempt == MAX_RETRIES:
                print("❌ WHOIS scan failed after maximum retries")
                save_scan_result(entry_id, {
                    "whois_info": {}
                })
            return None

    


    # print(f":white_tick: WHOIS info saved for {domain}")   



def custom_serializer(obj):
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)

def get_technologies(domain, entry_id):
    session = get_db_session()

    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    print("getting technology details")
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    company_id = company.id
    # Check if the domain includes a scheme
    if domain.startswith(('http://', 'https://')):
        url = domain
    else:
        # Try https first
        for scheme in ['https://', 'http://']:
            test_url = scheme + domain
            try:
                response = requests.head(test_url, timeout=5, allow_redirects=True)
                if response.status_code < 400:
                    url = test_url
                    break
            except requests.RequestException:
                continue
        else:
            return {"error": "Unable to connect using http or https."}

    try:
        tech_info = builtwith.parse(url)
        session.query(Vulnerabilities).filter(Vulnerabilities.company_id == company_id).update(
            {"info_http_headers": tech_info}
        )
        session.commit()
        # :white_tick: Save in JSON file
        # Print JSON-formatted resul
        save_scan_result(entry_id, {"new_tech_info" : tech_info}) 


        return tech_info
    except Exception as e:
        save_scan_result(entry_id, {"new_tech_info" : {}}) 
        return {"error": str(e)}
    



def get_dns_records(domain, entry_id):
    session = get_db_session()
    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    company_id = company.id
        # Extract the domain name if a scheme is present
    if domain.startswith(('http://', 'https://')):
        parsed_url = urlparse(domain)
        domain_name = parsed_url.netloc
    else:
        domain_name = domain
    print("scanning dns record")    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    dns_info = {}
    for record_type in record_types:
        try:
            answers = dns.resolver.resolve(domain_name, record_type)
            dns_info[record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            dns_info[record_type] = [f"Error: {e}"]
    
    session.query(Vulnerabilities).filter(Vulnerabilities.company_id == company_id).update(
            {"info_http_headers": dns_info}
        )
    session.commit()

    # Save the DNS information to a JSON file
    save_scan_result(entry_id, {"dns_info": dns_info})
    return dns_info
        #dns_record = get_dns_records(extract_domain(domain))
    # Print JSON-formatted resul
        # save_scan_result(entry_id, {"dns_info" : dns_record})    
    




def is_nmap_installed():
    return shutil.which("nmap") is not None  #  Check if Nmap exists

# Function to run Nmap scan
def run_nmap_scan(domain, entry_id):
    session = get_db_session()
    if not is_nmap_installed():  # Check before running
        return "Nmap is not installed or not found in PATH."


    parsed_url = urlparse(domain)
    domain_name = parsed_url.netloc or parsed_url.path  # Handles cases with or without scheme
 
    try:
        # :magnifying_glass: Get company_id from entry_id
        company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
        if not company:
            print(f":x: Company with entry_id {entry_id} not found.")
            return
        company_id = company.id
        # Running Nmap to scan top 200 vulnerability ports within 5 seconds
        print(f"nmapis running")
        result = subprocess.run(
            # ["nmap", "-T5", "-p-", "--min-rate=1000", "-Pn", "--open", "--script", "vuln", domain_name],
            # ["nmap", "-T5", "1", "--min-rate=1000", "--max-retries", "-Pn", "--open", "--script", "vuln", domain_name],
            ["nmap", "-T5", "--min-rate=1000", "--max-retries", "-Pn", "--open", domain_name],
            capture_output=True, text=True
        )
        # Extract only open ports using regex
        open_ports = re.findall(r"(\d+)/tcp\s+open", result.stdout)
        # open_ports = ["80"]
        print("open ports//////////////////////////////////", open_ports)

        if not open_ports:
            save_scan_result(entry_id, {"open_ports": json.dumps([])})
            save_scan_result(entry_id, {"vulnerable_ports": json.dumps([])})
            return "No open ports found!"
        
        vulnerable_ports= [port for port in open_ports if port not in ["80", "443"]]

        # Check if port 80 redirects to HTTPS
        if "80" in open_ports:
            try:
                
                http_url = f"http://{domain_name}"

                print(f"🔎 Checking HTTP to HTTPS redirection for {http_url}")
                response = requests.get(http_url, timeout=5, allow_redirects=True)

                if not response.url.startswith("https://"):
                    print(f"❗ Port 80 is open and does NOT redirect to HTTPS")
                    vulnerable_ports.append("80")
                else:
                    print(f"✅ Port 80 redirects to HTTPS: {response.url}")
            except Exception as e:
                print(f"⚠️ Could not verify HTTPS redirection for port 80: {e}")
        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
                    {"ports": vulnerable_ports}
                )
        session.commit()
        save_scan_result(entry_id, {"open_ports": open_ports})
        save_scan_result(entry_id, {"vulnerable_ports": vulnerable_ports})
        
        print(f":white_tick: Nmap Scan completed for {domain_name}")
        print('open ports')
        print(open_ports)
        print(type(open_ports))
        # actualResponse = {}
        # for port in open_ports:
        #     res = get_data_from_openAi(f"open ports={port}", entry_id=entry_id)
        #     actualResponse[port] = json.dumps(res)

        # # print('portsss')
        # # print(actualResponse)open_ports

        # save_scan_result(entry_id, {f"open_ports": json.dumps(actualResponse)})
        # for port in vulnerable_ports:
        #     res = get_data_from_openAi(f"vulnerable_ports={port}", entry_id=entry_id)
        #     actualResponse[port] = json.dumps(res)

        # # print('portsss')
        # # print(actualResponse)

        # save_scan_result(entry_id, {f"vulnerable_ports": json.dumps(actualResponse)})

    except subprocess.TimeoutExpired:
        print(f":x: Nmap scan timed out for {domain_name}")
    except Exception as e:
        save_scan_result(entry_id, {"open_ports": json.dumps([])})
        save_scan_result(entry_id, {"vulnerable_ports": json.dumps([])})
        print(f":x: Nmap scanning failed for {domain_name}: {e}")


# ✅ Define the top 20 security headers
TOP_20_HEADERS = [
    "Strict-Transport-Security", "X-Frame-Options", "X-XSS-Protection", "X-Content-Type-Options",
    "Referrer-Policy", "Content-Security-Policy", "Permissions-Policy", "Cache-Control",
    "Pragma", "Expires", "Access-Control-Allow-Origin", "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers", "Feature-Policy", "Expect-CT", "Public-Key-Pins",
    "NEL", "Server-Timing", "Cross-Origin-Resource-Policy", "Cross-Origin-Embedder-Policy"
]    
TOP_20_HEADERS = [h.lower() for h in TOP_20_HEADERS]


def check_missing_headers(domain, entry_id):
    
    session = get_db_session()
    try:
        session = get_db_session()
        # :magnifying_glass: Get company_id from entry_id
        company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
        if not company:
            print(f":x: Company with entry_id {entry_id} not found.")
            return
        company_id = company.id

        print(f"scanning for missing_headers")

        headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
                }

          # ✅ Try HTTP first
        response = requests.get(domain, headers=headers, timeout=10, allow_redirects=True)

        # ✅ Convert response headers to lowercase for case-insensitive matching
        response_headers = {header.lower(): value for header, value in response.headers.items()}


        # ✅ Check which security headers are missing (case-insensitive comparison)
        missing_headers = [header for header in TOP_20_HEADERS if header.lower() not in response_headers]
        print("missing headers")

        session.query(Vulnerabilities).filter_by(company_id=company_id).update(
            {"missing_headers": missing_headers}
        )
        session.commit()
        # save_scan_result(entry_id, {"missing_headers": missing_headers})
        print(f":white_tick: Missing Header Analysis completed for {domain}")
        
        # Ensure "Missing Headers" vulnerability exists
        vulnerable = session.query(Vulnerable).filter_by(name="Missing Headers").first()
        if not vulnerable:
            vulnerable = Vulnerable(name="Missing Headers")
            session.add(vulnerable)
            session.commit()

        actualResponse = {}
        for header in missing_headers:
            existing_response = session.query(VulnerableAIResponse).filter_by(
                vulnerable_id=vulnerable.id,
                key_word=header
            ).first()
            if existing_response:
                print(f"🔁 Found cached response for {header}")
                actualResponse[header] = existing_response.response
            else:
                print("wont go to the open_ai")
                res = get_data_from_openAi(f"missing_headers={header}", entry_id=entry_id)
                actualResponse[header] = json.dumps(res)

                new_response = VulnerableAIResponse(
                    vulnerable_id=vulnerable.id,
                    key_word=header,
                    response=res
                )
                session.add(new_response)
                session.commit()

                actualResponse[header] = res

        save_scan_result(entry_id, {'missing_headers': actualResponse})
        
        
    except Exception as e:
        save_scan_result(entry_id, {"missing_headers": {}})
        print(f":x: Header check failed for {domain}: {e}")

 


def get_http_headers(domain):
    

    try:
        response = requests.get(domain, timeout=5)
        return dict(response.headers)
    except requests.RequestException:
        return {}



    
    

def perform_fuzzing(domain, server, language, cms):
    

    # ✅ Convert to lowercase
    server = server.lower()
    language = language.lower()
    cms = cms.lower()

# Use relative paths for wordlists
    FUZZ_DIR = "fuzz_finder"
    WORDLISTS = {
        "php": os.path.join(FUZZ_DIR, "php_wordlist.txt"),
        "asp.net": os.path.join(FUZZ_DIR, "asp_wordlist.txt"),
        "node.js": os.path.join(FUZZ_DIR, "node_wordlist.txt"),
        "python": os.path.join(FUZZ_DIR, "python_wordlist.txt"),
        "java": os.path.join(FUZZ_DIR, "java_wordlist.txt"),
        "wordpress": os.path.join(FUZZ_DIR, "wordpress_wordlist.txt"),
        "joomla": os.path.join(FUZZ_DIR, "joomla_wordlist.txt"),
        "drupal": os.path.join(FUZZ_DIR, "drupal_wordlist.txt"),
        "apache": os.path.join(FUZZ_DIR, "apache_wordlist.txt"),
        "nginx": os.path.join(FUZZ_DIR, "nginx_wordlist.txt"),
    }    

# ✅ Choose the most relevant wordlist
    wordlist = None
    if language in WORDLISTS:
        wordlist = WORDLISTS[language]
    if cms in WORDLISTS:
         wordlist = WORDLISTS[cms]
    if server in WORDLISTS:
      wordlist = WORDLISTS[server]

    print(wordlist)
    # 🚫 If no wordlist is found or missing, skip the scan
    if not wordlist or not os.path.isfile(wordlist):
        print(f"⚠️ Wordlist not found for {language}/{cms}/{server}. Skipping scan.")
        return []
    
    print(f"✅ Using wordlist: {wordlist}")

    # 🔎 Find misconfigurations
    exposed_files = []
    try:
        with open(wordlist, "r") as f:
            endpoints = [line.strip() for line in f]

        for endpoint in endpoints:
            url = f"{domain}/{endpoint}"  # Try HTTP first
            try:
                response = requests.get(url, timeout=3)
                if response.status_code == 200:  # ✅ Found an exposed file!
                    print(f"🟢 Found: {url}")
                    exposed_files.append(url)
            except requests.RequestException:
                pass  # Ignore unreachable URLs

    except FileNotFoundError:
        pass  # No errors if the file is missing
   

    return exposed_files

def extract_links_with_params(domain):
    print("bueatyfull domain")
    print(domain)
    try:
        response = requests.get(domain, timeout=10)
        soup = BeautifulSoup(response.text, "html.parser")
        urls = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"]
            full_url = urljoin(domain, href)
            # Keep only URLs with query parameters (e.g., ?id=1)
            if "?" in full_url:
                urls.add(full_url)
        if len(urls)<=0:
            urls.add(domain)
        return list(urls)
    except Exception as e:
        print(f":warning: Error extracting links: {e}")
        return []
    


def run_xsstrike(domain,entry_id):
    print("dalfox domain")
    print(domain)
    session = get_db_session()
    # :white_tick: Get company ID
    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    company_id = company.id

    vulnerable = []
    urls_to_test = extract_links_with_params(f"{domain}")
    print("running xss_strike")
    MAX_RETRIES = 3
    GLOBAL_TIMEOUT = 300  # Max 5 minutes for the whole scan
    start_time = time.time()
    # if not urls_to_test:
    #     print(f":warning: No URLs with parameters found on {domain}")
    #     return None
    for url in urls_to_test:
        if time.time() - start_time > GLOBAL_TIMEOUT:
            print(f"⏰ Stopping scan early due to global timeout for {domain}")
            break
        try:
            print("running xss_strike1")
            print(f":mag: Scanning URL: {url}")
            attempt = 0
            success = False
            while attempt < MAX_RETRIES and not success:
                attempt += 1
                print(f":rocket: Attempt {attempt} for {url}")
                safe_url = urllib.parse.quote(url, safe=':/?&=%')
                command = ["dalfox", "url", safe_url, "--output", "json","--deep-detect","--silence","--skip-bav","--blind","--no-color","--only-poc"]
                result = subprocess.run(command, capture_output=True, text=True, timeout=180)
                output = result.stdout.strip()
                if not output:
                    print(f":warning: Dalfox returned empty output, retrying ({attempt}/{MAX_RETRIES})...")
                    time.sleep(2)  # wait 2 sec before retry
                    continue
                # 🛡️ Try parsing JSON safely
                try:
                    data = json.loads(output)
                except json.JSONDecodeError:
                    print(f":warning: Dalfox output not valid JSON, retrying ({attempt}/{MAX_RETRIES})...")
                    time.sleep(2)
                    continue
                if not data.get("poc"):
                    print(f":warning: No XSS vulnerabilities found for {url}")
                    success = True  # No need to retry if no vulnerabilities
                    break
                # Process vulnerabilities
                for finding in data["poc"]:
                    vulnerable.append({
                        "url": data.get("target"),
                        "parameter": finding.get("param"),
                        "payload": finding.get("payload"),
                        "type": finding.get("type")
                    })
                    success = True 
            if not success:
                print(f":x: Failed to scan {url} after {MAX_RETRIES} attempts.")  
            print(vulnerable) 
            # print(f":magnifying_glass: Scanning URL: {url}")
            # command = ["python3", "XSStrike/xsstrike.py", "--url", url,"--level 2","--threads 5", "--skip-dom" ,"--crawl", "--blind"]
            # result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            # output = result.stdout
            # for line in output.split("\n"):
            #     if "Vulnerable" in line:
            #         parts = line.split(":")
            #         if len(parts) >= 3:
            #             vuln_url = parts[0].strip()
            #             vuln_param = parts[1].strip()
            #             payload = parts[2].strip()
            #             vulnerable.append({ 
            #                 "url": vuln_url,
            #                 "parameter": vuln_param,
            #                 "payload": payload,
            #                 "type": "Reflected XSS"
            #             })
            # :white_tick: Store in DB
            session.query(Vulnerabilities).filter_by(company_id=company_id).update(
                {"xss_vulnerabilities": vulnerable}
            )
            session.commit()
            # :white_tick: Save in JSON file
            save_scan_result(entry_id, {"xss_vuln_data": vulnerable})
            
            print(f":white_tick: XSS Scan completed for {domain}")
            return vulnerable if vulnerable else None
        
        except Exception as e:
            save_scan_result(entry_id, {"xss_vuln_data": []})
            print(f":x: Error scanning {url}: {e}")
            continue










def scan_open_redirection(domain, entry_id):
    session = get_db_session()

    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    company_id = company.id
    """
    Scans a given domain for Open Redirection vulnerabilities using a wordlist.
    
    ✅ Loads payloads from `open_redirection/open_redirect_wordlist.txt`
    ✅ Checks if the site redirects to an external domain
    ✅ Avoids false positives from same-site redirects
    ✅ Ensures at least one redirect occurs
    """
    # Load the wordlist
    PAYLOAD_FILE = os.path.join(os.path.dirname(__file__), "open_redirection", "open_redirect_wordlist.txt")
    try:
        with open(PAYLOAD_FILE, "r", encoding="utf-8") as file:
            payloads = [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print(f"⚠️ Payload file not found: {PAYLOAD_FILE}")
        return []

    vulnerable_urls = []
    original_domain = urlparse(domain).netloc.lower()
    print("getting scan open redirection")

    for payload in payloads:
        # Directly use the payload as the test URL
        test_url = urljoin(domain, payload)

        try:
            response = requests.get(test_url, allow_redirects=True, timeout=5)
            final_url = response.url
            final_domain = urlparse(final_url).netloc.lower()

            # ✅ Strict Open Redirect Detection:
            if (
                response.history and  # Ensure redirection occurred
                final_domain and final_domain != original_domain and  # Ensure external redirection
                not final_domain.endswith(original_domain) and  # Prevent subdomain false positives
                not final_domain.startswith("www." + original_domain)  # Ignore "www" subdomains
                
            ):
                print(test_url)    
                
                vulnerable_urls.append({"payload": test_url, "redirected_to": final_url})
                print(f"[🔥] Open Redirect Found: {test_url} → {final_url}")

        except requests.RequestException:
            # save_scan_result(entry_id, {"open_redirection_vulnerabilities": vulnerable_urls})
            continue  # Ignore errors and timeouts

    session.query(Vulnerabilities).filter_by(company_id=company_id).update(
    {"open_redirection_vulnerabilities": vulnerable_urls}
    )
    session.commit()
    save_scan_result(entry_id, {"open_redirection_vulnerabilities": vulnerable_urls})
   
    print(f":white_tick: Open Redirection Scan completed for {domain}")

    return vulnerable_urls        

# #def detect_os_command_injection(domain):
OS_COMMAND_INJECTION_DIR = "OS_COMMAND_INJECTION_DIR"

def load_wordlist(file_name):
    """ Load wordlist from the OS_COMMAND_INJECTION_DIR folder """
    file_path = os.path.join(OS_COMMAND_INJECTION_DIR, file_name)
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return [line.strip() for line in file.readlines()]
    return []


def enumerate_directories(domain, entry_id):
    session = get_db_session()
    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    company_id = company.id
    """ ✅ Enumerate directories using wordlist and store in DB """
    detected_directories = []
    directory_wordlist = load_wordlist("directories.txt")  # ✅ Load directories list

    print(f"🔍 Enumerating directories for {domain}...")

    def is_same_domain(url1, url2):
        return urlparse(url1).netloc == urlparse(url2).netloc

    def is_valid_final_page(response):
        suspicious_keywords = ["login", "unauthorized", "access denied", "403 forbidden", "authentication required","page not found", "not found", "404 error", "this page doesn’t exist","doesn't exist",
    "does not exist", "sorry, we can’t find","404","the page you requested could not be found",
    "we can’t seem to find the page","the page you are looking for","no page found","this page is missing","oops! nothing here","requested url was not found","http 404","error 404","return to home page","back to homepage"]
        if response.status_code != 200:
            return not any(word in response.text.lower() for word in suspicious_keywords)
        return False
    
    # Function to handle HTTP requests with retries
    def safe_get(url, retries=3, backoff_factor=0.5, timeout=10):
        session = requests.Session()
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=backoff_factor,
            status_forcelist=[500, 502, 503, 504],  # Retry on server errors
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            return response
        except requests.RequestException as e:
            print(f"❌ Request failed for {url}: {e}")
            return None  # Return None if the request fails

    for directory in directory_wordlist:
        test_url = urljoin(domain, directory)

        try:
            response = requests.get(test_url, timeout=10, allow_redirects=True)
            final_url = response.url
            status = response.status_code

            # ✅ Direct 200
            if status == 200:
                if is_valid_final_page(response):
                    detected_directories.append({
                        "directory": directory,
                        "url": test_url,
                        "final_url": final_url,
                        "status": status,
                        "vulnerable": True
                    })
                    print(f"✅ Found (200): {test_url}")
                else:
                    detected_directories.append({
                        "directory": directory,
                        "url": test_url,
                        "final_url": final_url,
                        "status": 200,
                        "vulnerable": False
                    })
                    print(f"⚠️ Found (200, suspicious): {test_url}")

            # ✅ Manual Redirect Check
            elif status in [301, 302]:
                redirect_url = response.headers.get("Location")
                if redirect_url:
                    redirect_url = urljoin(test_url, redirect_url)
                    if not is_same_domain(test_url, redirect_url):
                        print(f"⛔ External redirect skipped: {test_url} → {redirect_url}")
                        continue

                    try:
                        redirected_response = requests.get(redirect_url, timeout=5, allow_redirects=True)
                        full_chain = [r.url for r in redirected_response.history] + [redirected_response.url]
                        final_status = redirected_response.status_code
                        if final_status == 200 and is_valid_final_page(redirected_response):
                            detected_directories.append({
                                "directory": directory,
                                "url": test_url,
                                "redirects_to": redirected_response.url,
                                "redirect_chain": full_chain,
                                "status": final_status,
                                "vulnerable": True
                            })
                            print(f"✅ Found via redirect: {test_url} → {redirected_response.url}")
                        else:
                            detected_directories.append({
                                "directory": directory,
                                "url": test_url,
                                "redirects_to": redirected_response.url,
                                "redirect_chain": full_chain,
                                "status": final_status,
                                "vulnerable": False
                            })
                            print(f"⚠️ Redirected but not valid (login/403/etc): {test_url}")
                    except Exception as e:
                        save_scan_result(entry_id, {"Directory_enumration_vulnerabilities": json.dumps({"directory": directory,
                                "url": test_url,
                                "redirects_to": redirected_response.url,
                                "redirect_chain": full_chain,
                                "status": final_status,
                                "vulnerable": False})})
                        print(f"❌ Failed redirect: {test_url} → {redirect_url} ({e})")


        except Exception as e:
        
            print(f"❌ Error checking {test_url}: {e}")

        
    print(detected_directories)   


    if(len(detected_directories) < 1):
        detected_directories.append({
                                "directory": directory,
                                "url": domain,
                                "redirects_to": None,
                                "redirect_chain": None,
                                "status": None,
                                "vulnerable": False
                            })
        
    vulnerable_entries = [entry for entry in detected_directories if entry["vulnerable"]]

    # 🛑 If no vulnerabilities found, return one safe default entry
    if not vulnerable_entries:
        vulnerable_entries.append({
            "directory": "/",
            "url": domain,
            "final_url": domain,
            "status": None,
            "vulnerable": False
        })


    session.query(Vulnerabilities).filter_by(company_id=company_id).update(
        {"Directory_enumration_vulnerabilities": vulnerable_entries}
    )
    session.commit()
    save_scan_result(entry_id, {"Directory_enumration_vulnerabilities": vulnerable_entries})
    
    print(f"✅ Open Redirection Scan completed for {domain}")



def check_clickjacking(domain, entry_id):
    session = get_db_session()
    company = session.query(CompanyInfo.id).filter(CompanyInfo.temp_id == entry_id).first()
    if not company:
        print(f":x: Company with entry_id {entry_id} not found.")
        return
    company_id = company.id
    """
    Checks if the given domain is vulnerable to Clickjacking.
    Returns a dictionary with the scan results.
    """
    print("getting clickjacking")
    try:
        # Send a GET request to fetch the headers
        url = f"{domain}" if not domain.startswith("http") else domain
        response = requests.get(url, timeout=100)

        # Extract security headers
        x_frame_options = response.headers.get("X-Frame-Options", "").lower()
        content_security_policy = response.headers.get("Content-Security-Policy", "").lower()

        # Check if the website is vulnerable
        vulnerable = False
        vulnerability_reason = ""

        if "deny" in x_frame_options or "sameorigin" in x_frame_options:
            vulnerability_reason = "Protected (X-Frame-Options is set correctly)"
        elif "frame-ancestors" in content_security_policy:
            vulnerability_reason = "Protected (CSP frame-ancestors is set)"
        else:
            vulnerability_reason = "Vulnerable! No X-Frame-Options or CSP protection found."
            vulnerable = True

        # Return the scan result
        clickjacking_result = {
            "domain": domain,
            "x_frame_options": x_frame_options if x_frame_options else "Not Set",
            "content_security_policy": content_security_policy if content_security_policy else "Not Set",
            "vulnerable": vulnerable,
            "message": vulnerability_reason
        }

    except requests.RequestException as e:
        save_scan_result(entry_id, {"Directory_enumration_vulnerabilities": json.dumps({'error': str(e)})})
        clickjacking_result = {"error": f"Failed to check Clickjacking for {domain}: {str(e)}"}
    
    # ✅ Save Clickjacking vulnerability in DB
    session.query(Vulnerabilities).filter_by(company_id=company_id).update(
        {"clickjacking_vulnerability": clickjacking_result}
    )
    session.commit()

    # ✅ Save Clickjacking scan result to JSON file
    save_scan_result(entry_id, {"clickjacking_vulnerability": clickjacking_result})
    

    print(f"✅ Clickjacking Scan completed for {domain}")


def update_scan_completion_status(entry_id):
    print("____________----------------------__________")
    print(f"from update_scan_complete function, entry_id: {entry_id}")
    file_path = os.path.join(SCAN_RESULTS_DIR, f"{entry_id}.json")

    if not os.path.exists(file_path):
        print("Scan result file does not exist.")
        return

    try:
        with open(file_path, "r") as file:
            scan_data = json.load(file)

        # Check if all values are scanned (i.e., not "not_scanned")
        # keys_to_check = ["missing_headers","xsstrike","clickjacking_vulnerability","xss_vuln_data","Directory_enumration_vulnerabilities"]
        keys_to_check = ["missing_headers","clickjacking_vulnerability","xss_vuln_data","Directory_enumration_vulnerabilities","vulnerable_ports"]
        all_scanned = all(scan_data.get(key) != "not_scanned" for key in keys_to_check)

        if all_scanned:
            print('________ inside all scanned _______')
            scan_data["status"] = "complete"

            scan_data = get_count(scan_data=scan_data)

            # Update the file
            with open(file_path, "w") as file:
                json.dump(scan_data, file, indent=4)
            print(f"[✔] Scan for {entry_id} marked as complete.")
        else:
            print(f"[⌛] Scan for {entry_id} still in progress...")

    except json.JSONDecodeError:
        print("❌ Failed to read scan result JSON - file might be corrupted or incomplete.")



def get_count(scan_data):
        print('get count initiated')
        domain = scan_data.get("url")
        def get_www_domain(domain):
            parsed = urlparse(domain)
            hostname = parsed.netloc or parsed.path  # fallback if netloc is empty
            if not hostname.startswith("www."):
                hostname = f"www.{hostname}"
            return hostname
        www_domain = get_www_domain(domain=domain)
        print("////////////////////////////////////////////")
        print(f"Error: The DNS response does not contain an answer to the question: {www_domain}. IN MX")

        # Count total checks performed
        total_checks = 0
        vulnerable_count = 0
        secure_count = 0
        keys_to_check = ["whois_info","http_headers","missing_headers","xss_vuln_data","Directory_enumration_vulnerabilities","dns_info","clickjacking_vulnerability","new_tech_info","open_redirection_vulnerabilities"]
        vulnerability_keys = ["missing_headers","clickjacking_vulnerability","xss_vuln_data","Directory_enumration_vulnerabilities","vulnerable_ports","open_redirection_vulnerabilities"]
        #✅ Count how many of the keys exist in scan_data
        total_checks = sum(1 for key in keys_to_check if key in scan_data)
        
        # click_data = scan_data.get("clickjacking_vulnerability")
        # if isinstance(click_data, dict):    
        #     if click_data.get("vulnerable") is True:
        #         vulnerable_count += 1
        #     elif click_data.get("vulnerable") is False:
        #         secure_count += 1

        clickJackingVulnerableCount = clickJacikingSecureCount = 0
        clickjacking_vulnerability= scan_data.get("clickjacking_vulnerability") or {}
        # if isinstance(clickjacking_vulnerability	, list):  
            # for entry in clickjacking_vulnerability:
        if isinstance(clickjacking_vulnerability, dict):
            found_vulnerability = False 
            if(clickjacking_vulnerability.get("vulnerable") is True):
                clickJackingVulnerableCount += 1
                found_vulnerability = True

        if not found_vulnerability:
                clickJacikingSecureCount += 1  


        VulnerablePortVulnerableCount = VelnerablePortsecureCount = 0
        vulnerable_ports = scan_data.get("vulnerable_ports") or [] 

        if isinstance(vulnerable_ports, list) and len(vulnerable_ports) > 0:
            VulnerablePortVulnerableCount += len(vulnerable_ports)  # Each missing header is a vulnerability
        else:
            VelnerablePortsecureCount += 1

        DirectoriesEnumrationVulnerabilityCount = DirectoriesEnumrationSecureCount = 0
        Directory_enumration_vulnerabilities= scan_data.get("Directory_enumration_vulnerabilities")
        if isinstance(Directory_enumration_vulnerabilities	, list): 
            found_vulnerability = False   
            for entry in Directory_enumration_vulnerabilities:
                if isinstance(entry, dict) and entry.get("vulnerable") is True:
                    DirectoriesEnumrationVulnerabilityCount += 1
                    found_vulnerability = True

            if not found_vulnerability:
                DirectoriesEnumrationSecureCount += 1   


        MissingheadersVulnerableCount = MissingheadersSecureCount = 0
        # ✅ Count missing headers individually as vulnerabilities
        missing_headers = scan_data.get("missing_headers")
        if isinstance(missing_headers, str):
            missing_headers = json.loads(missing_headers)
        print('json dump')
        print(missing_headers)

        if isinstance(missing_headers, dict) and len(missing_headers) > 0:
            MissingheadersVulnerableCount += len(missing_headers)  # Each missing header is a vulnerability
        else:
            MissingheadersSecureCount += 1


        xssVulnerableCount = xssSecureCount = 0
        xss_data = scan_data.get("xss_vuln_data") or []
        if isinstance(xss_data, list):
            xss_vuln_count = len(xss_data)
            if xss_vuln_count > 0:
                xssVulnerableCount += xss_vuln_count
            else:
                xssSecureCount += 1

        OpenredirectionVulnerabilityCount = OpenredirectionSecureCount = 0
        open_redirect = scan_data.get("open_redirection_vulnerabilities") or []
        if isinstance(open_redirect, list):
            open_redirect_count = len(open_redirect)
            if open_redirect_count > 0:
                OpenredirectionVulnerabilityCount += open_redirect_count
            else:
                OpenredirectionSecureCount += 1


        httpHeadersInfoCount = 0
        http_headers = scan_data.get("http_headers") 
        print("http_headers type")
        print(type(http_headers))
        if isinstance(http_headers, dict):
            httpHeadersInfoCount = len(http_headers)
            
        openPortInfoCount = 0
        openPorts = scan_data.get("open_ports") 
        print("open_ports")
        print(type(openPorts))
        print(openPorts)
        if isinstance(openPorts, list):
            print('inside if')
            openPortInfoCount = len(openPorts)        

        addCheck = addCheck = {'whois_info': {'dnssec': 'unsigned'},'dns_info':{'MX':[f"Error: The DNS response does not contain an answer to the question: {www_domain}. IN MX"]}};
        vulnerableAddCheck = {};

        addVulnerableCount = 0;
        

        for key, value in addCheck.items():
            res = utilities.extraVulnerabilitiesData(scan_data, key, value)
            vulnerableAddCheck[key] = res;

            for v in res.values():
                if v != {} and v != None and v != []:
                    addVulnerableCount += 1;



        vulnerable_count=sum([clickJackingVulnerableCount,VulnerablePortVulnerableCount,DirectoriesEnumrationVulnerabilityCount,MissingheadersVulnerableCount,xssVulnerableCount,OpenredirectionVulnerabilityCount])
        secure_count = sum([clickJacikingSecureCount,VelnerablePortsecureCount,DirectoriesEnumrationSecureCount,MissingheadersSecureCount,xssSecureCount,OpenredirectionSecureCount])
        scan_data["scan_summary"] = {
            "httpHeadersInfoCount": httpHeadersInfoCount,
            "openPortInfoCount": openPortInfoCount,
            "clickJackingVulnerableCount": clickJackingVulnerableCount,
            "VulnerablePortVulnerableCount": VulnerablePortVulnerableCount,
            "DirectoriesEnumrationVulnerabilityCount": DirectoriesEnumrationVulnerabilityCount,
            "MissingheadersVulnerableCount": MissingheadersVulnerableCount,
            "xssVulnerableCount": xssVulnerableCount,
            "OpenredirectionVulnerabilityCount" : OpenredirectionVulnerabilityCount,
            "total_count": total_checks,
            "vulnerable_count": vulnerable_count,
            "secure_count": secure_count,
            "addCount": addVulnerableCount,
            "addVulnerables": vulnerableAddCheck,
        }
        scan_data["status"] = "Completed"

        print("get count result is now showing")
        print(scan_data)
        return scan_data


        # save_scan_result(temp_id, {"scan_summary": scan_data})





def perform_full_scan(domain, entry_id):
    """Runs all security scans one by one and stores each result in the database."""
    session = get_db_session()  # Get DB session

    company_id = session.query(CompanyInfo.id).filter(CompanyInfo.id == entry_id).first();
    session.commit()
 
    # company_id = company_id.id

    print('hi_______->')
    print(company_id)
    domain=resolve_live_url(domain)
    print(domain)

     # 🔍 Step 1: Check if the domain is live
   

    try:

        process1 = multiprocessing.Process(target=run_nmap_scan, args=(domain, entry_id))
        process1.start()

        process2 = multiprocessing.Process(target=get_whois_info, args=(domain, entry_id))
        process2.start()

        process3 = multiprocessing.Process(target=check_missing_headers, args=(domain, entry_id))
        process3.start()

        process4 = multiprocessing.Process(target=run_xsstrike, args=(domain, entry_id))
        process4.start()

        process5 = multiprocessing.Process(target=scan_open_redirection, args=(domain, entry_id))
        process5.start()

        process6 = multiprocessing.Process(target=enumerate_directories, args=(domain, entry_id))
        process6.start()

        process7 = multiprocessing.Process(target=check_clickjacking, args=(domain, entry_id))
        process7.start()


        process8 = multiprocessing.Process(target=get_technologies, args=(domain, entry_id))
        process8.start()

        process9 = multiprocessing.Process(target=get_dns_records, args=(domain, entry_id))
        process9.start()


        # get_whois_info(domain, entry_id)







        scan_results = {}
        




    except Exception as e:
        print(f"❌ Error during scan: {e}")
        session.rollback()
    
    finally:
        session.close()


openai.api_key = "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"
def get_data_from_openAi(keyword, entry_id):
    # Extract the keyword or phrase from GET parameters
    # Debugging: Print the received keyword
    print(f"mega: {keyword}")
    # Check if the keyword is provided
    # if not keyword:
    #     print("enter......")
    #     return jsonify({"error": "Keyword must be provided"}), 400
    if keyword.startswith("missingheader="):
        header_name = keyword.split("=", 1)[1]
    else:
        header_name = keyword
    prompt = (
        f"You are a security expert. Provide detailed information about any known security vulnerabilities (CVEs) or general security weaknesses (CWEs) related to the HTTP header: {header_name}. "
        f"This includes risks introduced by the **absence or misconfiguration** of the header. Your response should help security teams understand the impact and how to fix it.\n\n"
        "Return the response in the following strict JSON format:\n"
        "{\n"
        '  "cve_id": "CVE-XXXX-XXXX",\n'
        '  "cwe_id": "CWE-XXX",\n'
        '  "cvss_score": 8.1,\n'
        '  "severity": "High",\n'
        '  "description": "Explain how the missing or misconfigured header weakens security.",\n'
        '  "recommendations": "Provide specific steps to mitigate the issue.",\n'
        f'  "keyword": "{keyword}"\n'
        "}\n\n"
        "If no relevant CVE is found, provide the most applicable CWE. Avoid using 'N/A' unless absolutely nothing applies."
    )
    try:
        print("enter")
        # Call OpenAI API
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",  # or "gpt-4"
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=1
        )
        # Get response content
        openai_response = response['choices'][0]['message']['content'].strip()
        print("OpenAI raw response:", openai_response)
        # Parse and return JSON response
        try:
            print("OpenAI raw response:", openai_response)
            response_json = (openai_response)
            print("\nParsed JSON:\n", json.dumps(response_json, indent=2))
            # return save_scan_result(entry_id, {header_name : response_json})    
            return response_json  
        except json.JSONDecodeError:
            print("\nFailed to parse JSON. Here’s the raw output:")
            # Handle bad JSON from OpenAI gracefully
            return jsonify({
                "cve_id": "N/A",
                "cvss_score": "N/A",
                "severity": "N/A",
                "description": "N/A",
                "keyword": keyword
            })
    except Exception as e:
        return jsonify({"error": f"Error with OpenAI API: {str(e)}"}), 500



@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json()
        if not data or "domain" not in data:
            return jsonify({"error": "No domain provided"}), 400
        
        domain = data["domain"]
        domain = resolve_live_url(domain)
        
        print("Received domain:", domain)
        
        if domain == None:
            print(f"⚠️ Skipping scans: {domain} is not live!")

             # Store the result immediately in DB
            # session.query(Vulnerabilities).filter_by(company_id=new_entry.id).update(
            #     {"scan_status": "Domain is not live"}
            # )
            # session.commit()
            return jsonify({"message": "Not Live","temp_id": None, "domain": domain})
    

        print(f"🚀 {domain} is live! Proceeding with scans...")
        # Get the latest temp_id and increment it (ensure uniqueness)
        now = datetime.now().timestamp();
        now = str(now);
        rand_temp_id_index = now.rfind('.');
        rand_temp_id = now[(rand_temp_id_index + 1):];

        max_temp_id = session.query(CompanyInfo.temp_id).filter(CompanyInfo.temp_id == rand_temp_id).first()

        new_temp_id = rand_temp_id;
        #Auto-increment



         # ✅ Generate a unique placeholder email
        #unique_email = f"unknown_{new_temp_id}@example.com"
        

        # Insert new company entry with unique temp_id
        new_entry = CompanyInfo(temp_id=new_temp_id, company_name=None,email=None, url=domain)
        session.add(new_entry)
        session.commit()  # ✅ Commit first to generate `id`
        company_id = new_entry.id

# ✅ Fetch the committed entry to ensure `id` is available
        session.refresh(new_entry)  # ✅ Guarantees new_entry.id exists in DB

        #session = get_db_session()

        # ✅ Verify company_id exists in DB before inserting
        company_exists = session.query(CompanyInfo).filter_by(id=new_entry.id).first()
        if not company_exists:
            raise Exception(f"Company ID {new_entry.id} not found in the database!")
        
        company_id = session.query(CompanyInfo.id).filter(CompanyInfo.id == company_id).first();
        session.commit()
        print('company_id')
        print(company_id)

        # Create initial scan structure
        initial_data = {
            "whois_info": "not_scanned",
            "http_headers": "not_scanned",
            "missing_headers": "not_scanned",
            "xss_vuln_data":"not_scanned",
            "Directory_enumration_vulnerabilities":"not_scanned",
            "open_ports":"not_scanned",
            "dns_info":"not_scanned",
            "clickjacking_vulnerability":"not_scanned",
            "new_tech_info":"not_scanned",
            "open_redirection_vulnerabilities":"not_scanned",
            "vulnerable_ports":"not_scanned",
            


            "scan_summary":"null"
            
        }

        # Save initial JSON to file
        file_path = os.path.join(SCAN_RESULTS_DIR, f"{new_temp_id}.json")
        with open(file_path, "w") as f:
            json.dump(initial_data, f, indent=4)


        http_headers = get_http_headers(domain)
        
        
      

        session.query(Vulnerabilities).filter_by(company_id=company_id.id).update(
            { "info_http_headers": http_headers}
        )
        session.commit()
        save_scan_result(new_temp_id, {"url": domain})
        save_scan_result(new_temp_id, {"http_headers": http_headers})
        print(f"✅ HTTP Header Analysis completed for {domain}")

        # whois_info = get_whois_info(domain, new_temp_id)

        # ✅ Start background scan
        process = multiprocessing.Process(target=perform_full_scan, args=(domain, new_temp_id))
        process.start()

        


        return jsonify({"message": "Scan started in the background","temp_id": new_temp_id, "domain": domain})

    except Exception as e:
        print(f"Error: {e}")  # Print error in Flask console
        session.rollback()  # Rollback changes if any error occurs
        return jsonify({"error": "Internal Server Error"}), 500  # Return JSON instead of HTML



        

@app.route("/scan/results/<temp_id>", methods=["GET"])
def get_scan_result(temp_id):

    """
    Route to fetch and return the scan result JSON data for a given `temp_id` (or company_id)
    """
    # Ensure SCAN_RESULTS_DIR is defined and accessible
    if not os.path.exists(SCAN_RESULTS_DIR):
        return jsonify({"error": "Scan results directory not found"}), 500
    
    update_scan_completion_status(temp_id)
    # Generate the path to the JSON file for this scan
    file_path = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")
    final_file = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")

    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                updated_data = json.load(file)  # <-- Might crash here

            # Add company info
            session = get_db_session()
            user = session.query(CompanyInfo.company_name, CompanyInfo.fullName, CompanyInfo.email)\
                          .filter(CompanyInfo.temp_id == temp_id).first()
            if user:
                updated_data['company_name'] = user.company_name
                updated_data['full_name'] = user.fullName
                updated_data['email'] = user.email


            return jsonify(updated_data)

        except json.JSONDecodeError as e:
            print(f"❌ JSONDecodeError while reading scan result for {temp_id}: {e}")
            return jsonify({"error": "Scan result is not yet fully saved. Try again shortly."}), 500

        except Exception as e:
            print(f"❌ Unexpected error while loading scan result for {temp_id}: {e}")
            return jsonify({"error": "Unexpected server error"}), 500

    else:
        return jsonify({"error": "Scan result not found for the given temp_id"}), 404
    
    # if os.path.exists(file_path):
    #     # Read the JSON file
    #     with open(file_path, 'r') as file:
    #         scan_data = json.load(file)

    
    # # 🔄 Check and update scan completion status
    #     # update_scan_completion_status(temp_id) 

    #     with open(file_path, "r") as file:
    #         updated_data = json.load(file)

    #     session = get_db_session()
    #     user = session.query(CompanyInfo.id, CompanyInfo.company_name, CompanyInfo.full_name).filter(CompanyInfo.temp_id == temp_id).first()
    #     updated_data['company_name'] = user.company_name
    #     updated_data['full_name'] = user.full_name

    #     return jsonify(updated_data)
    # else:
    #     # If the file doesn't exist, return an error message
    #     return jsonify({"error": "Scan result not found for the given temp_id"}), 404

@app.route('/scan/company/<company_id>', methods=['POST', 'OPTIONS'])
def scan_company(company_id):
    if request.method == 'OPTIONS':
        return '', 200
            
    return jsonify({"status": "success", "message": "Data received"})

@app.route('/scan/company/<company_id>/verify-otp', methods=['POST', 'OPTIONS'])
def scan_verify_otp(company_id):
    if request.method == 'OPTIONS':
        return '', 200
            
    return jsonify({"status": "success", "message": "Data received"})

@app.route("/scan/generate-otp/<int:temp_id>", methods=["POST"])
def generateOtp(temp_id):

    companyData = session.query(CompanyInfo).filter_by(temp_id=int(temp_id)).first()
    if not companyData:
        data = jsonify({'msg': 'There is not enough data...', "isGenerated": False})
        res = make_response(data) 
        res.delete_cookie('retries_attempted', domain=request.host)
        res.status_code = 400
        return res

    formData = request.get_json()

    if not formData or not 'email' in formData or not 'companyName' in formData or 'fullName' not in formData or 'phoneNumber' not in formData:
        res = make_response(jsonify({'isGenerated': False, 'msg': "Some data's are not presented", 'formData': formData}))
        res.status_code = 400
        return res

    company_name = str(formData['companyName'])
    email = str(formData['email'])
    full_name = str(formData['fullName'])
    phone_number = str(formData['phoneNumber'])

    otp = generate_otp()
    session.query(CompanyInfo).filter(CompanyInfo.temp_id == int(temp_id)).update(
        {
            "otp": int(otp), "company_name": company_name, "email": email,
            "fullName": full_name, "phone": phone_number
        }
    )
    session.commit()

    body = f"Your OTP is {otp}"
    sendOtp(receiver_email=email, otp=otp)

    return jsonify({"msg": "Otp generated", "isGenerated": True, "otp": otp})



@app.route("/scan/verify-otp/<int:temp_id>", methods=["POST"])
def verifyOtp(temp_id):

    companyData = session.query(CompanyInfo).filter_by(temp_id=int(temp_id)).first()
    if not companyData:
        data = jsonify({'msg': 'There is not enough data...', "isGenerated": False})
        res = make_response(data) 
        res.delete_cookie('retries_attempted', domain=request.host)
        res.status_code = 400
        return res

    formData = request.get_json()
    cookies = request.cookies
    otp = retries_attempted = None

    if not formData or not 'otp' in formData:
        res = make_response(jsonify({'isVerified': False, 'isMaxRetired': False}))
        res.status_code = 400
        return res
    else:
        otp = int(formData['otp'])
    
    if cookies and 'retries_attempted' in cookies:
        retries_attempted = cookies['retries_attempted']
    
    if not retries_attempted:
        retries_attempted = 1
    else:
        retries_attempted = int(retries_attempted) + 1

    if retries_attempted and int(retries_attempted) > 3:
        return jsonify({"msg": "max retries reached", "isMaxRetried": True, 'isVerified': False})
    
    
    company = session.query(CompanyInfo).filter(CompanyInfo.temp_id == int(temp_id)).first()

    isVerified = company.otp == otp

    retries_attempted = 3 if isVerified else retries_attempted
    isMaxVerified = True if isVerified else False

    data = jsonify({"msg": "Verified" if isVerified else "Not verified", "retries": retries_attempted, "isMaxRetried": isMaxVerified, "isVerified": isVerified})

    res = make_response(data)
    res.set_cookie(key='retries_attempted', value=str(retries_attempted), max_age=60*2)

    return res

@app.route("/get-skipped/<int:temp_id>", methods=["GET"])
def get_skipped(temp_id):
    
    file_path = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")

    if not os.path.exists(file_path):
        print("Scan result file does not exist.")
        return

    try:
        with open(file_path, "r") as file:
            scan_data = json.load(file)
        # Check if all values are scanned (i.e., not "not_scanned")
        # keys_to_check = ["missing_headers","xsstrike","clickjacking_vulnerability","xss_vuln_data","Directory_enumration_vulnerabilities"]
        scan_data["status"] = "complete"

        scan_data = get_count(scan_data=scan_data)

        # Update the file
        with open(file_path, "w") as file:
            json.dump(scan_data, file, indent=4)
        print(f"[✔] Scan for {temp_id} marked as complete.")

        return jsonify(scan_data)

    except json.JSONDecodeError:
        print("❌ Failed to read scan result JSON - file might be corrupted or incomplete.")

    pass

def generate_otp():
    return random.randint(100000, 999999)


@app.after_request
def add_cors_headers(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    response.headers.add('Access-Control-Allow-Credentials', 'true')
    return response
   


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)








def save_scan_result(temp_id, scan_data):
    """ ✅ Save scan data to a JSON file (creates if not exists) using temp_id """


    file_path = os.path.join(SCAN_RESULTS_DIR, f"{temp_id}.json")
    temp_path = file_path + ".tmp"

    try:
        # ✅ If the file exists, load existing data
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as file:
                try:
                    existing_data = json.load(file)
                except json.JSONDecodeError:
                    print(f"⚠️ Warning: Corrupted existing file for {temp_id}. Starting fresh.")
                    existing_data = {}
        else:
            existing_data = {}  # ✅ Create new JSON structure

        # ✅ Update with new scan data
        # Set timezone to Asia/Kolkata
        india_tz = pytz.timezone('Asia/Kolkata')
        now_in_india = datetime.now(india_tz)
        # Format scan end time
        scan_data["scan_end_time"] = now_in_india.strftime("%B %d, %Y at %I:%M %p").lstrip("0").replace(" 0", " ") # Remove leading zero and replace " 0" with " "
        existing_data.update(scan_data)  
