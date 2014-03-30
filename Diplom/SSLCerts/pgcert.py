#!/usr/bin/python
__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, ASN1
from subprocess import check_output
from datetime import datetime
from optparse import OptionParser, OptionGroup
from os import path, getuid
from time import time


DEFAULT_FIELDS = {'C': 'ru',
                  'ST': 'msk',
                  'L': 'msk',
                  'O': 'mephi',
                  'OU': 'kaf36',
                  'CN': check_output("whoami", shell=True).split('\n')[0],
                  'SC': ''}
DEFAULT_PASSWORD = '123456'


def password(*args, **kwargs):
    return DEFAULT_PASSWORD


def check_path(file_path):
    if not path.exists(file_path):
        print("ERROR: File path %s not exist" % file_path)
        exit(1)


def check_permissions():
    if getuid() != 0:
        print("Please, login as `root` and try again")
        exit(1)


def make_private_key(bits, output):
    rsa_key = RSA.gen_key(bits, 65537, callback=password)
    if not output:
        output = path.abspath(path.curdir) + "/mykey.pem"
    rsa_key.save_key(output, None)
    return 'Key was saved to %s' % output


def make_request(private_key_path, username, user_context, output):
    check_path(private_key_path)
    private_key = EVP.load_key(private_key_path, callback=password)
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
    if username:
        name.CN = username
    if user_context:
        context = user_context
    else:
        context = check_output("id -Z", shell=True).split('\n')[0]
    if not context:
        print('Command `id -Z` return with error code')
        exit(1)
    request.set_subject_name(name)
    stack = X509.X509_Extension_Stack()
    stack.push(X509.new_extension("selinuxContext", context, 0))
    request.add_extensions(stack)
    request.sign(private_key, 'sha1')
    if not output:
        output = path.abspath(path.curdir) + '/%s.csr' % DEFAULT_FIELDS['CN']
    request.save_pem(output)
    print(request.as_text())
    return 'Request was saved to %s' % output


def make_certificate(request_path, ca_private_key_file, ca_certificate_file, output):
    check_path(request_path)
    request = X509.load_request(request_path)
    public_key = request.get_pubkey()
    if not request.verify(public_key):
        print('Error verifying request')
        exit(1)
    subject = request.get_subject()
    ca_certificate = X509.load_cert(ca_certificate_file)
    ca_private_key = EVP.load_key(ca_private_key_file, callback=password)
    certificate = X509.X509()
    certificate.set_serial_number(time().as_integer_ratio()[0])
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
    extension_stack = X509.X509_Extension_Stack()
    extension = X509
    certificate.add_ext(X509.new_extension("selinuxContext", "test", 0))
    if not output:
        output = path.abspath(path.curdir) + '/%s.crt' % DEFAULT_FIELDS['CN']
    certificate.sign(ca_private_key, 'sha1')
    certificate.save(output)
    return 'Certificate was saved to %s' % output


def verify_certificate(certificate_path, ca_certificate_path):
    check_path(certificate_path)
    check_path(ca_certificate_path)
    certificate = X509.load_cert(certificate_path)
    ca_certificate = X509.load_cert(ca_certificate_path)
    ca_public_key = ca_certificate.get_pubkey()
    if certificate.verify(ca_public_key):
        return 'status verification ok'
    else:
        return 'status: verification failed'


def print_certificate(certificate_file_path):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    return certificate.as_text()


def print_request(request_file_path):
    check_path(request_file_path)
    request = X509.load_request(request_file_path)
    return request.as_text()


def get_subject_field(certificate_file_path, field):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    subject = certificate.get_subject()
    try:
        result = subject.__getattr__(field)
    except AttributeError:
        return 'No field %s in subject of %s' % (field, certificate_file_path)
    return result


def get_subject(certificate_file_path):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    return certificate.get_subject().as_text()


def get_issuer(certificate_file_path):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    return certificate.get_issuer().as_text()


def get_issuer_field(certificate_file_path, field):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    subject = certificate.get_subject()
    try:
        result = subject.__getattr__(field)
    except AttributeError:
        return 'No field %s in issuer of %s'


def make_ca(bits, cakey_file_path, cacert_file_path):
    make_private_key(bits, cakey_file_path)
    check_path(cakey_file_path)
    private_key = EVP.load_key(cakey_file_path, callback=password)
    name = X509.X509_Name()
    name.C = DEFAULT_FIELDS['C']
    name.ST = DEFAULT_FIELDS['ST']
    name.L = DEFAULT_FIELDS['L']
    name.O = DEFAULT_FIELDS['O']
    name.OU = DEFAULT_FIELDS['OU']
    name.CN = DEFAULT_FIELDS['O'] + '\'s CA'
    certificate = X509.X509()
    certificate.set_serial_number(time().as_integer_ratio()[0])
    certificate.set_version(3)
    certificate.set_subject(name)
    certificate.set_issuer(name)
    certificate.set_pubkey(private_key)
    not_before = ASN1.ASN1_UTCTIME()
    not_before.set_datetime(datetime.today())
    not_after = ASN1.ASN1_UTCTIME()
    not_after.set_datetime(datetime(datetime.today().year + 2, datetime.today().month, datetime.today().day))
    certificate.set_not_before(not_before)
    certificate.set_not_after(not_after)
    certificate.add_ext(X509.new_extension("basicConstraints", "CA:TRUE", 1))
#    certificate.add_ext(X509.new_custom_extension("1.2.3.4.5", "selinuxContext", "X509v3 SELinux Context", "test"))
    certificate.add_ext(X509.new_custom_extension("1.2.3.4.5", "selinuxContext", "X509v3 SELinux Context", "MyTest", 1))
    certificate.sign(private_key, 'sha1')
    certificate.save(cacert_file_path)
    print(certificate.as_text())
    return 'Certificate was saved to %s' % cacert_file_path


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [Main Options] options",
                          add_help_option=True,
                          description="This program use M2Crypto library and can generate X509 certificate "
                                      "with extension field SELinux Context")
    main_options = OptionGroup(parser, "Main Options")
    main_options.add_option("--genrsa", dest="genrsa", action="store_true", default=False,
                            help="generate private key with bits length")
    main_options.add_option("--genreq", dest="genreq", action="store_true", default=False,
                            help="generate request for private key")
    main_options.add_option("--gencert", dest="gencert", action="store_true", default=False,
                            help="generate certificate for user")
    main_options.add_option("--makeca", dest="makeca", action="store_true", default=False,
                            help="generate ca certificate and private key")
    parser.add_option_group(main_options)

    additional_group = OptionGroup(parser, "Additional options",)
    additional_group.add_option("--get-issuer", dest="issuer", action="store_true", default=False,
                                help="get issuer of certificate")
    additional_group.add_option("--get-subject", dest="subject", action="store_true", default=False,
                                help="get subject of certificate")
    additional_group.add_option("--field", dest="field", help="field name")
    additional_group.add_option("--text", dest="print_pem", action="store_true", default=False,
                                help="print request or certificate")
    additional_group.add_option("--verify", dest="verify", action="store_true", default=False,
                                help="verify certificate")
    additional_group.add_option("--output", type="string", dest="output", help="save to file output")
    parser.add_option_group(additional_group)

    request_group = OptionGroup(parser, "Request options")
    request_group.add_option("--pkey", dest="pkey", help="add path of private key")
    request_group.add_option("--user", dest="user", default=DEFAULT_FIELDS['CN'],
                             help="add username to certificate CN, default=%s" % DEFAULT_FIELDS['CN'])
    request_group.add_option("--context", dest="context", default=None, help="add user context to request")
    parser.add_option_group(request_group)

    pkey_group = OptionGroup(parser, "Private key options")
    pkey_group.add_option("--bits", dest="bits", type="int", default="2048",
                          help="bits for generate RSA-key, default: %default")
    parser.add_option_group(pkey_group)
    parser.add_option("--request", dest="request", help="add path to request file")
    parser.add_option("--cakey", dest="cakey", default="/etc/pki/CA/private/cakey.pem", type="string",
                      help="add CA key path to generate user's certificate, default: %default")
    parser.add_option("--cacert", dest="cacert", default="/etc/pki/CA/cacert.pem", type="string",
                      help="add CA certificate path to generate user's certificate, default: %default")
    parser.add_option("--cert", dest="certificate", help="add path of certificate")
    options, args = parser.parse_args()
    if options.genrsa and options.bits:
        print(make_private_key(options.bits, options.output))
    elif options.genreq and options.pkey:
        print(make_request(options.pkey, options.user, options.context, options.output))
    elif options.gencert and options.request:
#        check_permissions()
        print(make_certificate(options.request, options.cakey, options.cacert, options.output))
    elif options.verify and options.certificate and options.cacert:
        print(verify_certificate(options.certificate, options.cacert))
    elif options.issuer and options.certificate:
        print(get_issuer(options.certificate))
    elif options.issuer and options.field and options.certificate:
        print(get_issuer_field(options.certificate, options.field))
    elif options.subject and options.certificate:
        print(get_subject(options.certificate))
    elif options.subject and options.certificate and options.field:
        print(get_subject_field(options.output, options.field))
    elif options.print_pem and options.certificate:
        print(print_certificate(options.certificate))
    elif options.print_pem and options.request:
        print(print_request(options.request))
    elif options.makeca:
#        check_permissions()
        print(make_ca(options.bits, options.cakey, options.cacert))
    else:
        parser.print_help()
