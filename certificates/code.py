
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

from os import scandir
import datetime

roots = {}
intermediate_certs = {}

def load_certificate(file_name): 
    now = datetime.datetime.now()

    with open(file_name, 'rb') as f:
        pem_data = f.read()
        # if '.cer' in file_name.name:
        #     cert = x509.load_der_x509_certificate(pem_data, default_backend())
        # else:
            # cert = x509.load_pem_x509_certificate(pem_data, default_backend())
        cert = x509.load_pem_x509_certificate(pem_data, default_backend())

    # print(f"Loaded {cert.subject} {cert.serial_number}")
    # print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}")

    if cert.not_valid_after < now:
        # print(file_name, "EXPIRED (", cert.not_valid_after, ')') 
        return cert, False
    else:
        return cert, True

    # return cert, True

def build_chain(chain, cert):
    chain.append(cert)

    issuer = cert.issuer.rfc4514_string()
    subject = cert.subject.rfc4514_string()

    if issuer == subject and subject in roots:
        print("Chain completed")
        return chain

    if issuer in roots:
        return build_chain(chain, roots[issuer])
    elif issuer in intermediate_certs:
        print('found issuer')
        return build_chain(chain, intermediate_certs[issuer])

def validate_chain(chain):
    if len(chain) == 1:
        return True

    cert = chain[0]
    issuer = chain[1]

    issuer.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )

    return validate_chain(chain[1:])

def load_certificates(dir_name, roots, intermediate_certs):
    for entry in scandir(dir_name):
        if entry.is_dir() or not (any(x in entry.name for x in ['pem', 'cer'])):
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
load_certificates('certs/', roots, intermediate_certs)

c, valid = load_certificate('certs/gitlab.pem')

cert_chain = build_chain([], c)
print(cert_chain)

chain_valid = validate_chain(cert_chain)
print(chain_valid)
