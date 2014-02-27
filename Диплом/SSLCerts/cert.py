__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, ASN1
from subprocess import check_output, check_call
from datetime import datetime
from optparse import OptionParser
from os import path


DEFAULT_FIELDS = {'C': 'ru',
                  'ST': 'msk',
                  'L': 'msk',
                  'O': 'mephi',
                  'OU': 'kaf36',
                  'CN': str(check_output("whoami", shell=True).split('\n')[0])}


def make_private_key(bits, output):
    rsa_key = RSA.gen_key(bits, X509.RSA_F4)
    private_key = EVP.PKey()
    private_key.assign_rsa(rsa_key)
    if not output:
        output = path.abspath(path.curdir) + "/mykey.pem"
    else:
        output = path.abspath(path.curdir) + "/" + output
    private_key.save_key(output)
    return "Key was saved to %s" % output


def make_request(private_key, output):
    request = X509.Request()
    request.set_pubkey(private_key)
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
    nid = X509.obj_create("1.2.3.4.5", "SC", "SElinuxContext")
    if check_call("id -Z", shell=True):
        raise ValueError, 'Command `id -Z` return with error code'
    context = check_output("id -Z", shell=True).split('\n')[0]
    name.add_entry_by_nid(nid, X509.ASN1.MBSTRING_ASC, context, len=-1, loc=-1, set=0)
    request.set_subject_name(name)
    request.sign(private_key, 'sha1')
    request.save_pem(output)


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
    parser.add_option("--rsa", dest="bits", help="Generate private key with bits length")
    parser.add_option("--req", dest="private_key", help="Generate request for private_key")
    parser.add_option("-o", "--output", type="string", dest="output", help="Save to file output")
    options, args = parser.parse_args()
    output = options.output
    bits = int(options.bits)
    private_key = options.private_key
    if options.bits:
        print(make_private_key(bits, output))
    if options.private_key:
        print(make_request(private_key, output))