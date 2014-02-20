__author__ = 'dimv36'
from M2Crypto import RSA, X509, m2, EVP, Rand

# XXX Do I actually need more keys?
# XXX Check return values from functions


def generate_rsa_key():
    return RSA.gen_key(2048, m2.RSA_F4)


def make_public_key(key):
    public_key = EVP.PKey()
    public_key.assign_rsa(key)
    return public_key


def make_request(public_key):
    request = X509.Request()
    request.set_pubkey(public_key)
    name = X509.X509_Name()
    name.add_entry_by_txt(field='O', type=X509.ASN1.MBSTRING_ASC, entry='user@example', len=-1, loc=-1, set=0)
    object = m2.obj_txt2obj("1.2.3.4.5", 200)
    print(m2.obj_obj2nid(object))
    print(object)
#    m2.asn1_object_new("1.2.3.4.5", "SC", "SELinuxContext")
#    print(X509.new_extension("SELinuxContext", "user_u:user_t:user_r:s0-s3", 1))
#    print(X509.X509_Name.nid)
#    X509.X509_Name.nid = X509.X509_Name.nid + {'SC', 30, 'SelinuxContext'}
    request.set_subject_name(name)
    extension = X509.new_extension('SC', 'Hello there')
    extension_stack = X509.X509_Extension_Stack()
    extension_stack.push(extension)
    request.add_extensions(extension_stack)
    request.sign(public_key, 'sha1')
    return request


def make_certificate(request, ca_public_key):
    public_key = request.get_pubkey()
    if not request.verify(public_key):
        raise ValueError, 'Error verifying request'
    subject = request.get_subject()
    certificate = X509.X509()
    certificate.set_serial_number(1)
    certificate.set_version(2)
    certificate.set_subject(subject)
    issuer = X509.X509_Name()
    issuer.CN = 'CA'
    issuer.O = 'Test Organization'
    certificate.set_issuer(issuer)
    certificate.set_pubkey(public_key)
    notBefore = m2.x509_get_not_before(certificate.x509)
    notAfter = m2.x509_get_not_after(certificate.x509)
    m2.x509_gmtime_adj(notBefore, 0)
    m2.x509_gmtime_adj(notAfter, 60 * 60 * 24 * 30)
    extension = X509.new_extension('nsComment', 'M2Crypto generated certificate', 1)
    certificate.add_ext(extension)
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
    #print request.as_text()
    certificate = make_certificate(request, public_key)
    #print certificate.as_text()
    #print certificate.as_pem()
    certificate.save_pem('my_ca_cert.pem')
    #rsa_key.save_key('my_key.pem', 'aes_256_cbc')
