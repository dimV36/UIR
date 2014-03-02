#!/usr/bin/python
__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, ASN1
from subprocess import check_output
from datetime import datetime
from optparse import OptionParser
from os import path

DEFAULT_FIELDS = {'C': 'ru',
                  'ST': 'msk',
                  'L': 'msk',
                  'O': 'mephi',
                  'OU': 'kaf36',
                  'CN': str(check_output("whoami", shell=True).split('\n')[0])}


def make_public_key(bits, output):
    rsa_key = RSA.gen_key(bits, X509.RSA_F4)
    public_key = EVP.PKey()
    public_key.assign_rsa(rsa_key)
    if not output:
        output = path.abspath(path.curdir) + "/mykey.pem"
    else:
        output = path.abspath(path.curdir) + "/" + output
    public_key.save_key(output)
    return "Key was saved to %s" % output


def make_request(key_file, output):
    public_key = EVP.load_key(key_file)
    if not public_key:
        raise ValueError, "Not correct key path"
    request = X509.Request()
    request.set_pubkey(public_key)
    request.set_version(3)
    name = X509.X509_Name()
    fields = dict()
    fields['C'] = raw_input("Country Name (2 letter code) [%s]: " % DEFAULT_FIELDS['C'])
    fields['ST'] = raw_input("State or Province Name (full name) [%s]: " % DEFAULT_FIELDS['ST'])
    fields['L'] = raw_input("Locality Name (eg, city) [%s]: " % DEFAULT_FIELDS['L'])
    fields['O'] = raw_input("Organization Name (eg, company) [%s]: " % DEFAULT_FIELDS['O'])
    fields['OU'] = raw_input("Organization Unit Name (eg, section) [%s]: " % DEFAULT_FIELDS['OU'])
    fields['CN'] = raw_input("Common Name (eg, your name) [%s]: " % DEFAULT_FIELDS['CN'])
    for key in fields.keys():
        if len(fields[key]) == 0:
            fields[key] = DEFAULT_FIELDS[key]
    name.C = fields['C']
    name.ST = fields['ST']
    name.L = fields['L']
    name.O = fields['O']
    name.OU = fields['OU']
    name.CN = fields['CN']
    context = check_output("id -Z", shell=True).split('\n')[0]
    if not context:
        raise ValueError, 'Command `id -Z` return with error code'
    name.SC = context
    request.set_subject_name(name)
    request.sign(public_key, 'sha1')
    if not output:
        output = path.abspath(path.curdir) + "/%s.csr" % DEFAULT_FIELDS['CN']
    else:
        output = path.abspath(path.curdir) + "/" + output
    request.save_pem(output)
    print(request.as_text())
    return "Request was saved to %s" % output


def make_certificate(request_file, ca_public_key_file, ca_certificate_file, output):
    request = X509.load_request(request_file)
    public_key = request.get_pubkey()
    if not request.verify(public_key):
        raise ValueError, 'Error verifying request'
    subject = request.get_subject()
    ca_certificate = X509.load_cert(ca_certificate_file)
    ca_public_key = EVP.load_key(ca_public_key_file)
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
    certificate.sign(ca_public_key, 'sha1')
    print(certificate.as_text())
    certificate.save(output)
    return "Certificate was saved to %s" % output

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] filename", version="%prog 1.0", add_help_option=True)
    parser.add_option("--rsa", dest="bits", help="Generate private key with bits length")
    parser.add_option("--req", dest="public_key", help="Generate request for private_key")
    parser.add_option("--key", dest="ca_public_key", help="Add CA key path to generate user's certificate")
    parser.add_option("--cert", dest="ca_certificate", help="Add CA certificate path to generate user's certificate")
    parser.add_option("--request", dest="request", help="Add path to request file")
    parser.add_option("-o", "--output", type="string", dest="output", help="Save to file output")
    options, args = parser.parse_args()
    output = options.output
    bits = options.bits
    public_key = options.public_key
    ca_public_key = options.ca_public_key
    ca_certificate = options.ca_certificate
    request = options.request
    if options.bits:
        print(make_public_key(int(bits), output))
    elif options.public_key:
        print(make_request(public_key, output))
    elif options.request and options.ca_public_key and options.ca_certificate:
        print(make_certificate(request, ca_public_key, ca_certificate, output))
    else:
        parser.print_help()
