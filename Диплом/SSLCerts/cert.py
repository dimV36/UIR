__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, Rand, ASN1
from subprocess import check_output, check_call
from datetime import datetime
from optparse import OptionParser

# -*- coding: utf-8 -*-

DEFAULT_FIELDS = {'C': 'ru',
                  'ST': 'msk',
                  'L': 'msk',
                  'O': 'mephi',
                  'OU': 'kaf36',
                  'CN': str(check_output("whoami", shell=True).split('\n')[0])}
bits = 1024


def make_public_key(bits):
    rsa_key = RSA.gen_key(bits, X509.RSA_F4)
    public_key = EVP.PKey()
    public_key.assign_rsa(rsa_key)
    return public_key


def make_request(public_key, path):
    request = X509.Request()
    request.set_pubkey(public_key)
    request.set_version(3)
    name = X509.X509_Name()
    fields = dict()
    fields['C'] = raw_input("Country Name (2 letter code) [ru]: ")
    fields['ST'] = raw_input("State or Province Name (full name) [msk]: ")
    fields['L'] = raw_input("Locality Name (eg, city) [msk]: ")
    fields['O'] = raw_input("Organization Name (eg, company) [mephi]: ")
    fields['OU'] = raw_input("Organization Unit Name (eg, section) [kaf36]: ")
    fields['CN'] = raw_input("Common Name (eg, your name) [your_name]: ")
    for key in fields.keys():
        if len(fields[key]) == 0:
            fields[key] = DEFAULT_FIELDS[key]
    name.C = fields['C']
    name.ST = fields['ST']
    name.L = fields['L']
    name.O = fields['O']
    name.OU = fields['OU']
    name.CN = fields['CN']
    nid = X509.obj_create("1.2.3.4.5", "SC", "SElinuxContext")
    if check_call("id -Z", shell=True):
        raise ValueError, 'Command `id -Z` return with error code'
    context = check_output("id -Z", shell=True).split('\n')[0]
    name.add_entry_by_nid(nid, X509.ASN1.MBSTRING_ASC, context, len=-1, loc=-1, set=0)
    request.set_subject_name(name)
    request.sign(public_key, 'sha1')
    request.save_pem(path)


def make_certificate(request, ca_public_key):
    public_key = request.get_pubkey()
    if not request.verify(public_key):
        raise ValueError, 'Error verifying request'
    subject = request.get_subject()
    certificate = X509.X509()
    certificate.set_serial_number(1)
    certificate.set_version(3)
    certificate.set_subject(subject)
    issuer = X509.X509_Name()
    issuer.CN = 'CA'
    issuer.O = 'Test Organization'
    not_before = ASN1.ASN1_UTCTIME()
    not_before.set_datetime(datetime.today())
    not_after = ASN1.ASN1_UTCTIME()
    not_after.set_datetime(datetime(datetime.today().year + 1, datetime.today().month, datetime.today().day))
    certificate.set_not_before(not_before)
    certificate.set_not_after(not_after)
    certificate.set_issuer(issuer)
    certificate.set_pubkey(public_key)
    certificate.sign(ca_public_key, 'sha1')
    return certificate

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options] filename", version="%prog 1.0")
    parser.add_option("--genrsa", "--rsa", dest="bits", help="Generate RSA-key with bits length")
    parser.add_option("--output", dest="output", help="Save to file output")
    (options, args) = parser.parse_args()
    

