#!/usr/bin/python
__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, ASN1
from subprocess import Popen, PIPE
from datetime import datetime
from optparse import OptionParser
from os import path

DEFAULT_FIELDS = {'C': 'ru',
                  'ST': 'msk',
                  'L': 'msk',
                  'O': 'mephi',
                  'OU': 'kaf36',
                  'CN': str(Popen("whoami", stdout=PIPE).communicate()[0]).split('\n')[0]}
DEFAULT_PASSWORD = '123456'


def password(*args, **kwargs):
    return DEFAULT_PASSWORD


def make_private_key(bits, output):
    rsa_key = RSA.gen_key(bits, X509.RSA_F4)
    private_key = EVP.PKey()
    private_key.assign_rsa(rsa_key)
    if not output:
        output = path.abspath(path.curdir) + "/mykey.pem"
    else:
        output = path.abspath(path.curdir) + "/" + output
    private_key.save_key(output, callback=password)
    return "Key was saved to %s" % output


def make_request(private_key_file, output):
    private_key = EVP.load_key(private_key_file, callback=password)
    if not private_key:
        raise ValueError, "Not correct key path"
    request = X509.Request()
    request.set_pubkey(private_key)
    request.set_version(3)
    name = X509.X509_Name()
    name.C = DEFAULT_FIELDS['C']
    name.ST = DEFAULT_FIELDS['ST']
    name.L = DEFAULT_FIELDS['L']
    name.O = DEFAULT_FIELDS['O']
    name.OU = DEFAULT_FIELDS['OU']
    name.CN = DEFAULT_FIELDS['CN']
    context = str(Popen(["id", "-Z"], stdout=PIPE).communicate()[0]).split('\n')[0]
    if not context:
        raise ValueError, 'Command `id -Z` return with error code'
    name.SC = context
    request.set_subject_name(name)
    request.sign(private_key, 'sha1')
    if not output:
        output = path.abspath(path.curdir) + "/%s.csr" % DEFAULT_FIELDS['CN']
    else:
        output = path.abspath(path.curdir) + "/" + output
    request.save_pem(output)
    print(request.as_text())
    return "Request was saved to %s" % output


def make_certificate(request_file, ca_private_key_file, ca_certificate_file, output):
    request = X509.load_request(request_file)
    public_key = request.get_pubkey()
    if not request.verify(public_key):
        raise ValueError, 'Error verifying request'
    subject = request.get_subject()
    ca_certificate = X509.load_cert(ca_certificate_file)
    ca_private_key = EVP.load_key(ca_private_key_file, callback=password)
    certificate = X509.X509()
    certificate.set_serial_number(1)
    certificate.set_version(3)
    certificate.set_subject(subject)
    issuer = ca_certificate.get_issuer()
    not_before = ASN1.ASN1_UTCTIME()
    not_before.set_datetime(datetime.today())
    not_after = ASN1.ASN1_UTCTIME()
    not_after.set_datetime(datetime(datetime.today().year + 1, datetime.today().month, datetime.today().day))
    certificate.set_not_before(not_before)
    certificate.set_not_after(not_after)
    certificate.set_issuer(issuer)
    certificate.set_pubkey(public_key)
    certificate.add_ext(X509.new_extension("basicConstraints", "CA:FALSE", 1))
    if not output:
        output = path.abspath(path.curdir) + "/%s.cert" % DEFAULT_FIELDS['CN']
    else:
        output = path.abspath(path.curdir) + "/" + output
    certificate.sign(ca_private_key, 'sha1')
    print(certificate.as_text())
    certificate.save(output)
    return "Certificate was saved to %s" % output


def verify_certificate(certificate_file, ca_certificate):
    certificate = X509.load_cert(certificate_file)
    if not certificate:
        raise ValueError, 'Error loading certificate file'
    ca_certificate = X509.load_cert(ca_certificate)
    ca_public_key = ca_certificate.get_pubkey()
    if not ca_certificate:
        raise ValueError, 'Error loading certificate key file'
    if certificate.verify(ca_public_key):
        return 'status verification ok'
    else:
        return 'status: verification failed'


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] filename", version="%prog 1.0", add_help_option=True)
    parser.add_option("--genrsa", dest="genrsa", action="store_true", default="False",
                      help="Generate private key with bits length")
    parser.add_option("--genreq", dest="genreq", action="store_true", default="False",
                      help="Generate request for private_key")
    parser.add_option("--gencert", dest="gencert", action="store_true", default="False", help="Generate certificate")
    parser.add_option("--verify", dest="verify", action="store_true", default="False", help="Verify certificate")
    parser.add_option("--bits", dest="bits", type="int", help="Bits for generate RSA-key")
    parser.add_option("--request", dest="request", help="Add path to request file")
    parser.add_option("--cakey", dest="cakey", default="/etc/pki/CA/private/cakey.pem", type="string",
                      help="Add CA key path to generate user's certificate")
    parser.add_option("--cacert", dest="cacert", default="/etc/pki/CA/cacert.pem", type="string",
                      help="Add CA certificate path to generate user's certificate")
    parser.add_option("--pkey", dest="pkey", help="Add path of private key")
    parser.add_option("--cert", dest="certificate", help="Add path of certificate")
    parser.add_option("-o", "--output", type="string", dest="output", help="Save to file output")
    options, args = parser.parse_args()
    bits = options.bits
    request = options.request
    cakey = options.cakey
    cacert = options.cacert
    pkey = options.pkey
    certificate = options.certificate
    output = options.output
    if True == options.genrsa and options.bits:
        print(make_private_key(bits, output))
    elif True == options.genreq and options.pkey:
        print(make_request(pkey, output))
    elif True == options.gencert and options.request:
        print(make_certificate(request, cakey, cacert, output))
    elif True == options.verify and options.certificate and options.cacert:
        print(verify_certificate(certificate, cacert))
    else:
        parser.print_help()