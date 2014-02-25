__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, Rand, ASN1
from subprocess import check_output, check_call
from datetime import datetime

# -*- coding: utf-8 -*-

# XXX Do I actually need more keys?
# XXX Check return values from functions


def generate_rsa_key():
    return RSA.gen_key(2048, X509.RSA_F4)


def make_public_key(key):
    public_key = EVP.PKey()
    public_key.assign_rsa(key)
    return public_key


def make_request(public_key):
    request = X509.Request()
    request.set_pubkey(public_key)
    request.set_version(3)
    name = X509.X509_Name()
    name.add_entry_by_txt(field='O', type=X509.ASN1.MBSTRING_ASC, entry='user@example', len=-1, loc=-1, set=0)
    nid = X509.obj_create("1.2.3.4.5", "SC", "SelinuxContext")
    if check_call("id -Z", shell=True):
        print("error when command `id -Z` was called")
        exit(1)
    context = check_output("id -Z", shell=True).split('\n')[0]
    name.add_entry_by_nid(nid, X509.ASN1.MBSTRING_ASC, context, len=-1, loc=-1, set=0)
    request.set_subject_name(name)
    request.sign(public_key, 'sha1')
    return request


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


def ca():
    rsa_key = generate_rsa_key()
    public_key = make_public_key(rsa_key)
    request = make_request(public_key)
    certificate = make_certificate(request, public_key)
    return (certificate, public_key)


if __name__ == '__main__':
    Rand.load_file('../randpool.dat', -1)
    rsa_key = generate_rsa_key()
    public_key = make_public_key(rsa_key)
    request = make_request(public_key)
    print request.as_text()
    certificate = make_certificate(request, public_key)
    print certificate.as_text()
    print certificate.as_pem()
    certificate.save_pem('my_ca_cert.pem')
    rsa_key.save_key('my_key.pem', 'aes_256_cbc')
