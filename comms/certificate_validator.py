

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

from os import scandir
import datetime

class Certificate_Validator():

    def __init__(self, trusted_cert_list, cert_list, crl_list):
        self.roots = {}
        self.intermediate_certs = {}
        self.crls = []

        print('ole')
        for d in trusted_cert_list:
            self.load_certificates(d, True)
            print(f'Loaded {d}')
        for d in cert_list:
            self.load_certificates(d)
            print(f'Loaded {d}')
        for d in crl_list:
            self.load_crls(d)
            print(f'Loaded {d}')

    def load_certificate(self, file_name): 
        now = datetime.datetime.now()

        with open(file_name, 'rb') as f:
            pem_data = f.read()
            if '.cer' in file_name.name:
                cert = x509.load_der_x509_certificate(pem_data, default_backend())
            else:
                cert = x509.load_pem_x509_certificate(pem_data, default_backend())
            # cert = x509.load_pem_x509_certificate(pem_data, default_backend())

        # print(f"Loaded {cert.subject} {cert.serial_number}")
        # print(f"Valid from {cert.not_valid_before} to {cert.not_valid_after}")

        if cert.not_valid_after < now:
            # print(file_name, "EXPIRED (", cert.not_valid_after, ')') 
            return cert, False
        else:
            return cert, True

    def load_crl(self, file_name):
        with open(file_name, 'rb') as f:
            crl_data = f.read()
            # crl = x509.load_pem_x509_crl(crl_data, default_backend())
            crl = x509.load_der_x509_crl(crl_data, default_backend())
        return crl

    def build_chain(self, chain, cert):
        chain.append(cert)

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        if issuer == subject and subject in self.roots:
            print("Chain completed")
            return chain

        if issuer in self.roots:
            return build_chain(chain, self.roots[issuer])
        elif issuer in self.intermediate_certs:
            print('found issuer')
            return build_chain(chain, self.intermediate_certs[issuer])

    def validate_chain(self, chain):
        if len(chain) == 1:
            return True

        cert = chain[0]
        issuer = chain[1]

        try:
            issuer.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except cryptography.exceptions.InvalidSignature:
            return False

        for crl in self.crls:
            if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
                return False

        return self.validate_chain(chain[1:], self.crls)

    def load_certificates(self, dir_name, trusted=False):
        for entry in scandir(dir_name):
            if entry.is_dir() or not (any(x in entry.name for x in ['pem', 'cer'])):
                continue
            c, valid = self.load_certificate(entry)
            if not valid:
                continue
            # print('Loading', entry.name, '(', c.subject.rfc4514_string(), ')')
            if trusted:
                self.roots[c.subject.rfc4514_string()] = c
            else:
                self.intermediate_certs[c.subject.rfc4514_string()] = c

    def load_crls(self, dir_name):
        for entry in scandir(dir_name):
            if entry.is_dir() or not (any(x in entry.name for x in ['crl'])):
                continue
            crl = self.load_crl(entry)
            self.crls.append(crl)

    def validate_certificate(self, cert):
        chain = self.build_chain([], cert)
        is_valid = self.validate_chain(chain)

        return is_valid



# c, valid = load_certificate('certs/user_certs/cc_cert.pem')

# cert_chain = build_chain([], c)
# print(cert_chain)

# chain_valid = validate_chain(cert_chain, crls)
# print(chain_valid)
