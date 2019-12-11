from cryptography import x509
from cryptography.hazmat.backends import default_backend

pem_data = None

with open('gitlab.pem', 'rb') as f:
    pem_data = f.read()

if not pem_data is None:
    print('Certificate successfully imported.')

cert = x509.load_pem_x509_certificate(pem_data, default_backend())

print()
print('Certificate Subject: ', cert.subject)
print()
print('Certificate Issuer: ', cert.issuer)

