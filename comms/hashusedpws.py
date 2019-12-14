from cryptography.hazmat.primitives import hashes, serialization, padding, hmac
from cryptography.hazmat.backends import default_backend
import re

def hash_pw(pw):
        h = hashes.Hash(hashes.SHA512(), backend=default_backend())
        h.update(pw.encode())
        return h.finalize()

with open('userdb','rb') as f:
    file = f.read().decode()

lines = re.split('\n',file)
elems = [re.split(':',line) for line in lines]
user_pws = [elem[2:3] for elem in elems]    
print(user_pws)


for pw in user_pws:
    print(hash_pw(pw[0]))

