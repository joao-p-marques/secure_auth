import PyKCS11
import binascii

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

lib ='/usr/local/lib/libpteidpkcs11.so'

class CC_authenticator():

    def __init__(self):
        # lib ='/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so'
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        self.pkcs11.load(lib)

        self.slots = pkcs11.getSlotList()

        # for slot in slots:
        #     print(pkcs11.getTokenInfo(slot))

        self.all_attr = list(PyKCS11.CKA.keys())

        #Filter attributes
        self.all_attr = [e for e in all_attr if isinstance(e, int)]
        self.session = pkcs11.openSession(slot)

        self.private_key = None
        self.get_pk()

        self.cert = None

    def get_attr_list(self):
        for obj in self.session.findObjects():
            # Get object attributes
            attr = self.session.getAttributeValue(obj, self.all_attr)

            # Create dictionary with attributes
            attr = dict(zip(map(PyKCS11.CKA.get, self.all_attr), attr))

            print('Label:', attr['CKA_LABEL'])

    def get_pk(self):
        self.private_key = session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION KEY')]
            )[0]

    def sign_text(self, text):
        mechanism = PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, None)
        # text = b'text to sign'

        signature = bytes(session.sign(private_key, text, mechanism))
        # print(signature)
        return signature

    def get_certificate(self):
        # cert = session.findObjects([
        #             (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        #             (PyKCS11.CKA_LABEL,'CITIZEN AUTHENTICATION CERTIFICATE')]
        #             )[0]
        if not self.cert:
            self.cert = x509.load_der_x509_certificate(bytes(attr['CKA_VALUE']), default_backend())
        return self.cert.public_bytes(
            encoding=serialization.Encoding.PEM
        )


