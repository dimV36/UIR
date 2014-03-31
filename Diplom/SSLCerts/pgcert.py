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
    print('Key was saved to %s' % output)


def make_request(private_key_path, username, user_context, output, is_printed):
    check_path(private_key_path)
    private_key = EVP.load_key(private_key_path, callback=password)
    request = X509.Request()
    request.set_pubkey(private_key)
    request.set_version(2)
    name = X509.X509_Name()
    name.C = DEFAULT_FIELDS['C']
    name.ST = DEFAULT_FIELDS['ST']
    name.L = DEFAULT_FIELDS['L']
    name.O = DEFAULT_FIELDS['O']
    name.OU = DEFAULT_FIELDS['OU']
    name.CN = DEFAULT_FIELDS['CN']
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
    if is_printed:
        print(request.as_text())
    print('Request was saved to %s' % output)


def make_certificate(request_path, ca_private_key_file, ca_certificate_file, output, is_printed):
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
    certificate.set_version(2)
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
    selinux_extension = request.get_extension_by_name("selinuxContext")
    if not selinux_extension:
        print("No extension selinuxContext in request %s" % request_path)
        exit(1)
    certificate.add_ext(selinux_extension)
    certificate.add_ext(X509.new_extension("basicConstraints", "CA:FALSE", 1))
    if not output:
        output = path.abspath(path.curdir) + '/%s.crt' % DEFAULT_FIELDS['CN']
    certificate.sign(ca_private_key, 'sha1')
    certificate.save(output)
    if is_printed:
        print(certificate.as_text())
    print('Certificate was saved to %s' % output)


def verify_certificate(certificate_path, ca_certificate_path):
    check_path(certificate_path)
    check_path(ca_certificate_path)
    certificate = X509.load_cert(certificate_path)
    ca_certificate = X509.load_cert(ca_certificate_path)
    ca_public_key = ca_certificate.get_pubkey()
    if certificate.verify(ca_public_key):
        print('Status verification: OK')
    else:
        print('Status: verification: FAIL')


def print_certificate(certificate_file_path):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    print(certificate.as_text())


def print_request(request_file_path):
    check_path(request_file_path)
    request = X509.load_request(request_file_path)
    print(request.as_text())


def get_subject(certificate_file_path):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    print(certificate.get_subject().as_text())


def get_issuer(certificate_file_path):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    print(certificate.get_issuer().as_text())


def get_extension(certificate_file_path, name):
    check_path(certificate_file_path)
    certificate = X509.load_cert(certificate_file_path)
    try:
        extension = certificate.get_ext(name)
    except LookupError:
        print("Certificate %s does not has extension %s" % (certificate_file_path, name))
    else:
        print(extension.get_value())


def make_ca(bits, cakey_file_path, cacert_file_path, is_printed):
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
    certificate.set_version(2)
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
    certificate.sign(private_key, 'sha1')
    certificate.save(cacert_file_path)
    print('Certificate was saved to %s' % cacert_file_path)
    if is_printed:
        print(certificate.as_text())


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [Main Options] options",
                          add_help_option=True,
                          description="This program use M2Crypto library and can generate X509 certificate "
                                      "with X509v3 extension SELinux Context")
    main_options = OptionGroup(parser, "Main Options")
    main_options.add_option("--genkey", dest="genkey", action="store_true", default=False,
                            help="generate private RSA key")
    main_options.add_option("--genreq", dest="genreq", action="store_true", default=False,
                            help="generate certificate request")
    main_options.add_option("--gencert", dest="gencert", action="store_true", default=False,
                            help="generate certificate for user")
    main_options.add_option("--makeca", dest="makeca", action="store_true", default=False,
                            help="generate ca certificate and private key")
    parser.add_option_group(main_options)

    pkey_group = OptionGroup(parser, "Private key options")
    pkey_group.add_option("--bits", dest="bits", type="int", default=2048, help="set length of key, default: %default")
    parser.add_option_group(pkey_group)

    req_group = OptionGroup(parser, "Request options")
    req_group.add_option("--user", dest="user", default=DEFAULT_FIELDS['CN'],
                         help="add username to request, default: %default")
    req_group.add_option("--secontext", dest="secontext", default=None,
                         help="add selinux context of user, default: %default")
    parser.add_option_group(req_group)

    input_options = OptionGroup(parser, "Input options")
    input_options.add_option("--pkey", dest="pkey", help="add location of private key")
    input_options.add_option("--request", dest="request", help="add location of certificate request")
    input_options.add_option("--certificate", dest="certificate", help="add location of certificate")
    input_options.add_option("--cacert", dest="cacert", default="/etc/pki/CA/cacert.pem",
                             help="add location of ca certificate, default: %default")
    input_options.add_option("--cakey", dest="cakey", default="/etc/pki/CA/private/cakey.pem",
                             help="add location of ca private key, default: %default")
    parser.add_option_group(input_options)

    output_options = OptionGroup(parser, "Output options")
    output_options.add_option("--output", dest="output", help="save to file")
    output_options.add_option("--text", dest="text", action="store_true", default=False,
                              help="request or certificate after generation")
    parser.add_option_group(output_options)

    info_options = OptionGroup(parser, "Info options")
    info_options.add_option("--issuer", dest="issuer", action="store_true", default=False,
                            help="get issuer of certificate")
    info_options.add_option("--subject", dest="subject", action="store_true", default=False,
                            help="get subject of certificate")
    info_options.add_option("--extension", dest="extension", help="get extension of certificate")
    info_options.add_option("--print", dest="print_pem", action="store_true", default=False,
                            help="print certificate or request")
    info_options.add_option("--verify", dest="verify", action="store_true", default=False, help="verify certificate")
    parser.add_option_group(info_options)

    options, args = parser.parse_args()
    if options.genkey and options.bits:
        make_private_key(options.bits, options.output)
    elif options.genreq and options.pkey:
        make_request(options.pkey, options.user, options.secontext, options.output, options.text)
    elif options.gencert and options.request:
        check_permissions()
        make_certificate(options.request, options.cakey, options.cacert, options.output, options.text)
    elif options.verify and options.certificate and options.cacert:
        verify_certificate(options.certificate, options.cacert)
    elif options.issuer and options.certificate:
        get_issuer(options.certificate)
    elif options.subject and options.certificate:
        get_subject(options.certificate)
    elif options.print_pem and options.certificate:
        print_certificate(options.certificate)
    elif options.certificate and options.extension:
        get_extension(options.certificate, options.extension)
    elif options.print_pem and options.request:
        print_request(options.request)
    elif options.makeca:
        check_permissions()
        make_ca(options.bits, options.cakey, options.cacert, options.text)
    else:
        parser.print_help()