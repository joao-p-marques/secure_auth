import PyKCS11
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

lib ='/usr/local/lib/libpteidpkcs11.so'
# lib ='/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'
pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load(lib)

slots = pkcs11.getSlotList()

for slot in slots:
    print(pkcs11.getTokenInfo(slot))

all_attr = list(PyKCS11.CKA.keys())

#Filter attributes
all_attr = [e for e in all_attr if isinstance(e, int)]
session = pkcs11.openSession(slot)

for obj in session.findObjects():
    # Get object attributes
    attr = session.getAttributeValue(obj, all_attr)
    
    # Create dictionary with attributes
    attr = dict(zip(map(PyKCS11.CKA.get, all_attr), attr))
    
    print('Label:', attr['CKA_LABEL'])

private_key = session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')]
            )[0]

mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
text = b'text to sign'

signature = bytes(session.sign(private_key, text, mechanism))
print(signature)

# cert = session.findObjects([
#             (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
#             (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION CERTIFICATE')]
#             )[0]
cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), default_backend())

print(cert)
print(cert.public_bytes(
    encoding=serialization.Encoding.PEM
    )
)

with open('cc_cert.pem', 'wb') as f:
    f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

print()
print(cert.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

