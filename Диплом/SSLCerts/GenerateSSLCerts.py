__author__ = 'dimv36'
from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join


def generate_ca():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    ca = crypto.X509()
    ca.set_version(3)
    ca.set_serial_number(1)
    ca.get_subject().CN = "main.ca.ru"
    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(24 * 60 * 60)
    ca.set_issuer(ca.get_subject())
    ca.set_pubkey(key)
    ca.add_extensions([crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
                      crypto.X509Extension("keyUsage", True,
                                           "keyCertSign, cRLSign"),
                      crypto.X509Extension("subjectKeyIdentifier", False, "hash",
                                           subject=ca)])
    ca.sign(key, "sha1")
    open("cakey.pem", "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open("cert.pem", "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))
    verify(key, ca)


def verify(key, cert):
    context = SSL.Context(SSL.TLSv1_METHOD)
    context.use_privatekey(key)
    context.use_certificate(cert)
    try:
        context.check_privatekey()
    except SSL.Error:
        print("Incorrect key")
    else:
        print("Key match certificate")


if __name__ == "__main__":
    generate_ca()


