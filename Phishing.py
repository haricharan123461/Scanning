import re#
import whois
import socket
import ssl
import tldextract
from datetime import datetime
from urllib.parse import urlparse
import requests
from pysafebrowsing import SafeBrowsing
from bs4 import BeautifulSoup


api_key = 'AIzaSyAq2yOEBeK6xCxJ81K3ir7-CT2qMMAyZh8'
safebrowsing = SafeBrowsing(api_key)



def check_https_secure(url):
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme != 'https':
            return None

        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return True
        else:
            return None
    except requests.exceptions.SSLError:
        return False
    except Exception:
        return None

def check_domain_age(url):
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        domain_age = (datetime.now() - creation_date).days
        if domain_age < 180:
            return False
        return True
    except Exception:
        return None

def check_ip_address_in_url(url):
    try:
        result = urlparse(url)
        if re.match(r'\d+\.\d+\.\d+\.\d+', result.netloc):
            return False
        return True
    except Exception:
        return False

def google_safe_browsing(url):
    try:
        result = safebrowsing.lookup_urls([url])
        if result[url]['malicious']:
            return False
        return True
    except Exception as e:
        print(f"Error checking Safe Browsing API: {e}")
        return None

def check_redirection_chain(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=10)
        if response.history:
            print("Redirection Chain:")
            for i, resp in enumerate(response.history):
                print(f"Redirect {i + 1}: {resp.url} (Status Code: {resp.status_code})")

                https_status = check_https_secure(resp.url)
                whois_status = check_domain_age(resp.url)
                ip_status = check_ip_address_in_url(resp.url)
                safe_browsing_status = google_safe_browsing(resp.url)

                print(f"  - HTTPS: {https_status}")
                print(f"  - WHOIS: {whois_status}")
                print(f"  - IP: {ip_status}")
                print(f"  - Safe Browsing: {safe_browsing_status}")

                if not all([https_status, whois_status, ip_status, safe_browsing_status]):
                    print(f"Redirection URL could be potentially unsafe: {resp.url}")
                    return False

        final_url = response.url
        print(f"Final URL after redirects: {final_url}")

        https_status = check_https_secure(final_url)
        whois_status = check_domain_age(final_url)
        ip_status = check_ip_address_in_url(final_url)
        safe_browsing_status = google_safe_browsing(final_url)

        if all([https_status, whois_status, ip_status, safe_browsing_status]):
            print("Final URL is safe.")
            return True
        else:
            print("Final URL could be potentially unsafe.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"Error during request: {e}")
        return False

def check_external_links(url):
    try:

        base_domain = tldextract.extract(url).registered_domain
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')

        links = soup.find_all('a', href=True)
        all_checks_passed = True

        for link in links:
            href = link['href']
            if href.startswith('#') or href.startswith('javascript:'):
                continue


            href = requests.compat.urljoin(url, href)
            link_domain = tldextract.extract(href).registered_domain


            if link_domain == base_domain:
                continue


            https_status = check_https_secure(href)
            whois_status = check_domain_age(href)
            ip_status = check_ip_address_in_url(href)
            safe_browsing_status = google_safe_browsing(href)

            print(f"Validating external link {href}:")
            print(f"  - HTTPS: {https_status}")
            print(f"  - WHOIS: {whois_status}")
            print(f"  - IP: {ip_status}")
            print(f"  - Safe Browsing: {safe_browsing_status}")


            score = 0
            if https_status in [True, None]:
                score += 1
            if whois_status in [True, None]:
                score += 1
            if ip_status:
                score += 1
            if safe_browsing_status:
                score += 1

            if score < 3:
                print(f"External link {href} could be potentially unsafe.")
                all_checks_passed = False

        return all_checks_passed
    except Exception as e:
        print(f"Error checking external links: {e}")
        return False

def is_phishing(url):
    https_status = check_https_secure(url)
    whois_status = check_domain_age(url)
    ip_status = check_ip_address_in_url(url)
    safe_browsing_status = google_safe_browsing(url)
    redirection_status = check_redirection_chain(url)
    external_links_status = check_external_links(url)

    print(f"HTTPS and SSL Certificate Validity: {https_status}")
    print(f"Domain Age Validity: {whois_status}")
    print(f"IP Address in URL Check: {ip_status}")
    print(f"Google Safe Browsing Status: {safe_browsing_status}")
    print(f"Redirection Chain Validity: {redirection_status}")
    print(f"External Links Check: {external_links_status}")

    score = sum(
        1 for status in [
            https_status,
            whois_status,
            ip_status,
            safe_browsing_status,
            redirection_status,
            external_links_status
        ] if status in [True, None]
    )

    if score >= 6:
        return "Detection complete, URL appears safe!"
    else:
        return "Detection complete, URL could be potentially unsafe!"


url = input("Enter the URL to check: ")
result = is_phishing(url)
print(result)
