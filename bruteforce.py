import requests
from itertools import product

DNS_CHARACTERS = 'abcdefghijklmnopqrstuvwxzy0123456789-_'


def gen_subdomains(base_domain, min, max):
    for i in range(min, max + 1):
        for c in product(DNS_CHARACTERS, repeat=i):
            yield (f'{"".join(c)}.{base_domain}')


def read_subdomains_from_file(host, filename):
    with open(filename) as f:
        for domain in f:
            yield f'{domain.strip()}.{host}'


def send_request(url: str, host: str):
    headers = {'Host': host}
    try:
        r = requests.get(url, verify=True, headers=headers)
        resp = r.text
        print(f"Host: {headers['Host']} Status: {r.status_code} Length: {len(r.text)}")
    except:
        print(f'ERROR Connecting to {url} using Host {host}')
        return 0, 0, 'ERROR'
    return r.status_code, len(r.text), r.text


def bruteforce_virtualhost(url: str, host: str, reference_request, min, max):
    findings = []
    for domain in gen_subdomains(host, min, max):
        r = send_request(url, domain)
        if reference_request != r:
            print (f'Found candidate {r}')
            findings.append(r)
    return findings


def use_list_virtualhost(url: str, host: str, reference_request, file):
    findings = []
    for domain in read_subdomains_from_file(host, file):
        r = send_request(url, domain)
        if reference_request != r:
            print (f'Found candidate {r}')
            findings.append(r)
    return findings


HOST = "hackycorp.com"
reference_url = f'http://{HOST}'
reference_req = send_request(reference_url, f'a.{HOST}')
#findings = bruteforce_virtualhost(reference_url, HOST, reference_req, 1, 1)
findings = use_list_virtualhost(reference_url, HOST, reference_req, 'subdomains-1000.txt')
if len(findings) > 0:
    print("**** FINDINGS:")
    for finding in findings:
        print(finding)
else:
    print('NO FINDINGS')
