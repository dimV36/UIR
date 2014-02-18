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
                      crypto.X509Extension("keyUsage", True, "keyCertSign, cRLSign"),
                      crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca),
                      crypto.X509Extension("SEContext", False, "context")])
    ca.sign(key, "sha1")
    open("cakey.pem", "wt").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open("cert.pem", "wt").write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca))


def sign_certificate_by_ca():
    ca_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, "ca.pem")
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, "ca.pem")
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    certificate = crypto.X509()
    certificate.get_subject().CN = "node1.example.com"
    certificate.set_serial_number(1)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(24 * 60 * 60)
    certificate.set_issuer(ca_certificate.get_subject())
    certificate.set_pubkey(key)
    certificate.sign(ca_key, "sha1")


def generate_certificate_request():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    request = crypto.X509Req()
    request.get_subject().CN = "node1.example.com"
    request.set_pubkey(key)
    request.sign(key, "sha1")
    open("key.pem", "wr").write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    open("req.csr", "wr").write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))


def generate_certificate_by_request():
    ca_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, "ca.pem")
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, "ca.pem")
    request = crypto.load_certificate_request(crypto.FILETYPE_PEM, open("req.csr").read())
    certificate = crypto.X509()
    certificate.set_subject(request.get_subject())
    certificate.set_serial_number(1)
    certificate.gmtime_adj_notBefore(0)
    certificate.gmtime_adj_notAfter(24 * 60 * 60)
    certificate.set_issuer(ca_certificate.get_subject())
    certificate.set_pubkey(request.get_pubkey())
    certificate.sign(ca_key, "sha1")
    open("cert.pem", "wr").write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))


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
