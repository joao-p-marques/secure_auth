
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from os import scandir
import datetime

roots = {}
intermediate_certs = {}

def load_certificate(file_name): 
    now = datetime.datetime.now()

    with open(file_name, 'rb') as f:
        pem_data = f.read()
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    # print(f"Loaded {cert.serial_number}")
    # print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}")

    if cert.not_valid_after < now:
        # print(file_name, "EXPIRED (", cert.not_valid_after, ')') 
        return cert, False
    else:
        return cert, True

    # return cert, True

def build_issuers(chain, cert, depth=0):
    if depth > 10:
        return

    chain.append(cert)
    print(chain)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in roots:
        print("Chain completed")
        return True

    if issuer in roots:
        return build_issuers(chain, roots[issuer], depth+1)
    elif issuer in intermediate_certs:
        print('found issuer')
        return build_issuers(chain, intermediate_certs[issuer], depth+1)

def load_certificates(dir_name, roots, intermediate_certs):
    for entry in scandir(dir_name):
        if entry.is_dir() or not ('pem' in entry.name or 'crt' in entry.name):
            continue
        c, valid = load_certificate(entry)
        if not valid:
            continue
        # print('Loading', entry.name, '(', c.subject.rfc4514_string(), ')')
        if any(x in entry.name for x in ['Root', 'ROOT', 'Trust', 'TRUST']): # and 'crt' in entry.name:
            roots[c.subject.rfc4514_string()] = c
        else:
            intermediate_certs[c.subject.rfc4514_string()] = c


load_certificates('/etc/ssl/certs', roots, intermediate_certs)
load_certificates('.', roots, intermediate_certs)

c, valid = load_certificate('gitlab.pem')

build_issuers([], c)
