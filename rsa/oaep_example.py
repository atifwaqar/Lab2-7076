from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256


def rsa_oaep_demo():
    key = RSA.generate(2048)
    pub = key.publickey()

    pt = b"oaep demo"
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    ct = cipher.encrypt(pt)

    plain = PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(ct)
    return plain == pt


if __name__ == "__main__":
    print("OAEP round-trip:", rsa_oaep_demo())
