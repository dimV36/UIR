#!/usr/bin/python
__author__ = 'dimv36'
from M2Crypto import RSA, X509, EVP, ASN1, BIO, SMIME
from selinux import security_check_context_raw, getcon_raw
from datetime import datetime
from optparse import OptionParser, OptionGroup
from os import path, getuid, getlogin
from time import time
from re import findall


DEFAULT_FIELDS = dict(C='ru', ST='msk', L='msk', O='mephi', OU='kaf36', CN=getlogin())
CAKEY = '/etc/pki/CA/private/cakey.pem'
CACERT = '/etc/pki/CA/cacert.pem'
DIGITAL_SIGNATURE_PATH = '/etc/pki/certs'
DEFAULT_PASSWORD = '123456'


def password(*args, **kwargs):
    return DEFAULT_PASSWORD


def check_path(file_path):
    if not path.exists(file_path):
        print('ERROR: File path %s not exist' % file_path)
        exit(1)


def check_selinux_context(context):
    if context:
        try:
            security_check_context_raw(options.secontext)
        except OSError:
            print('ERROR: Invalid SELinux context in argument')
            exit(1)


def check_permissions():
    if getuid() != 0:
        print('Please, login as `root` and try again')
        exit(1)


def make_level_and_category_sets(context):
    level_range = findall(r's(\d+)', context.split(':')[3])
    level_range = [int(element) for element in level_range]
    level_set = set()
    if len(level_range) == 1:
        level_set.add(level_range[0])
    else:
        level_set = {element for element in range(level_range[0], level_range[1] + 1)}

    category = str()
    try:
        category = context.split(':')[4]
    except IndexError:
        pass
    category_set = set()
    if category:
        category_range = findall(r'c(\d+)\.c(\d+)', category)
        for subrange in category_range:
            replace = str()
            for index in range(int(subrange[0]), int(subrange[1]) + 1):
                replace += 'c%s,' % index
            replace = replace[:-1]
            category = category.replace(str(r'c%s.c%s' % (subrange[0], subrange[1])), replace)
    category_set = set(findall(r'c(\d+)', category))
    category_set = {int(element) for element in category_set}
    return level_set, category_set


def verify_user_context(user, current_context):
    main_user_context = get_extension(DIGITAL_SIGNATURE_PATH + '/%s.crt' % user, 'selinuxContext')
    if not main_user_context:
        return False
    main_level, main_category = make_level_and_category_sets(main_user_context)
    current_level, current_category = make_level_and_category_sets(current_context)
    if current_level.issubset(main_level) and current_category.issubset(main_category):
        return True
    else:
        return False


def sign(private_key_path, certificate_path, request_path):
    request = X509.load_request(request_path)
    text = BIO.MemoryBuffer(request.as_pem())
    smime = SMIME.SMIME()
    smime.load_key(private_key_path, certificate_path)
    sign_request = smime.sign(text)
    sign_request_file = BIO.openfile(request_path + '.sign', 'w')
    smime.write(sign_request_file, sign_request)
    sign_request_file.close()
    print('Signing request was saved to %s' % request_path + '.sign')


def verify(certificate_path, ca_certificate_path, sign_request_path, output):
    smime = SMIME.SMIME()
    certificate = X509.load_cert(certificate_path)
    if not certificate:
        print('ERROR: Unable to load certificate %s' % certificate_path)
        exit(1)
    stack = X509.X509_Stack()
    stack.push(certificate)
    smime.set_x509_stack(stack)
    store = X509.X509_Store()
    store.load_info(ca_certificate_path)
    smime.set_x509_store(store)
    pks7, data = SMIME.smime_load_pkcs7(sign_request_path)
    clear_text = smime.verify(pks7, data)
    if not output:
        output = path.abspath(path.curdir) + '/%s.csr' % DEFAULT_FIELDS['CN']
    if clear_text:
        request = X509.load_request_string(clear_text)
        request.save(output)
        print('Verification OK')
        print('Request file was saved to %s' % output)
    else:
        print('Verification failed')


def make_private_key(bits, output):
    key_pair = RSA.gen_key(bits, 65537, callback=password)
    if not output:
        output = path.abspath(path.curdir) + '/mykey.pem'
    key_pair.save_key(output, None)
    print('Key was saved to %s' % output)


def make_request(private_key_path, username, user_context, critical, output, is_printed):
    check_path(private_key_path)
    key_pair = EVP.load_key(private_key_path, callback=password)
    request = X509.Request()
    request.set_pubkey(key_pair)
    request.set_version(2)
    name = X509.X509_Name()
    name.C = DEFAULT_FIELDS['C']
    name.ST = DEFAULT_FIELDS['ST']
    name.L = DEFAULT_FIELDS['L']
    name.O = DEFAULT_FIELDS['O']
    name.OU = DEFAULT_FIELDS['OU']
    name.CN = username
    if user_context:
        context = user_context
    else:
        context = getcon_raw()[1]
    if not context:
        print('Can not get SELinux context for user %s' % username)
        exit(1)
    request.set_subject_name(name)
    stack = X509.X509_Extension_Stack()
    stack.push(X509.new_extension('selinuxContext', context, int(critical)))
    request.add_extensions(stack)
    request.sign(key_pair, 'sha1')
    if not output:
        output = path.abspath(path.curdir) + '/%s.csr' % DEFAULT_FIELDS['CN']
    request.save_pem(output)
    if is_printed:
        print(request.as_text())
    print('Request was saved to %s' % output)


def make_certificate(request_path, ca_private_key_file, ca_certificate_file, output, is_digital, is_printed):
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
    selinux_extension = request.get_extension_by_name('selinuxContext')
    if not selinux_extension:
        print('ERROR: No extension selinuxContext in request %s' % request_path)
        exit(1)
    if not is_digital:
        if not verify_user_context(subject.CN, selinux_extension.get_value()):
            print('ERROR: Invalid SELinux context in request file %s' % request_path)
            exit(1)
        else:
            print('INFO: SELinux context is valid')
    certificate.add_ext(selinux_extension)
    certificate.add_ext(X509.new_extension('basicConstraints', 'CA:FALSE', 1))
    if is_digital:
        certificate.add_ext(X509.new_extension('keyUsage', 'Digital Signature', 1))
    if not output:
        output = path.abspath(path.curdir) + '/%s.crt' % DEFAULT_FIELDS['CN']
    certificate.sign(ca_private_key, 'sha1')
    certificate.save(output)
    if is_printed:
        print(certificate.as_text())
    print('Certificate was saved to %s' % output)


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
        print('Certificate %s does not has extension %s' % (certificate_file_path, name))
    else:
        return extension.get_value()


if __name__ == '__main__':
    parser = OptionParser(usage='usage: %prog [Main Options] options',
                          add_help_option=True,
                          description='This program use M2Crypto library and can generate X509 certificate '
                                      'with X509v3 extension SELinux Context')
    main_options = OptionGroup(parser, 'Main Options')
    main_options.add_option('--genkey', dest='genkey', action='store_true', default=False,
                            help='generate private key')
    main_options.add_option('--genreq', dest='genreq', action='store_true', default=False,
                            help='generate certificate request')
    main_options.add_option('--gencert', dest='gencert', action='store_true', default=False,
                            help='generate certificate for user')
    main_options.add_option('--sign', dest='sign', action='store_true', default=False,
                            help='sign request by user\'s digital signature')
    main_options.add_option('--verify', dest='verify', action='store_true', default=False,
                            help='verify signature of request by user digital signature')
    parser.add_option_group(main_options)

    pkey_group = OptionGroup(parser, 'Private key options')
    pkey_group.add_option('--bits', dest='bits', type=int, default=2048,
                          help='set length of private key, default: %default')
    parser.add_option_group(pkey_group)

    req_group = OptionGroup(parser, 'Request options')
    req_group.add_option('--user', dest='user', default=DEFAULT_FIELDS['CN'],
                         help='set CN of request, default: %default')
    req_group.add_option('--secontext', dest='secontext', help='add SELinux context to request')
    req_group.add_option('--critical', dest='critical', action='store_true', default=False,
                         help='set critical of selinuxContext extension, default: %default')
    parser.add_option_group(req_group)

    certificate_group = OptionGroup(parser, 'Certificate options')
    certificate_group.add_option('--signature', dest='signature', action='store_true', default=False,
                                 help='add extension keyUsage with value \'Digital signature\' to certificate, '
                                      'default: %default')
    parser.add_option_group(certificate_group)

    input_options = OptionGroup(parser, 'Input options')
    input_options.add_option('--pkey', dest='pkey', help='set location of private key')
    input_options.add_option('--request', dest='request', help='set location of certificate request')
    input_options.add_option('--certificate', dest='certificate', help='set location of certificate')
    input_options.add_option('--cakey', dest='cakey', default=CAKEY,
                             help='set location of ca private key, default: %default')
    input_options.add_option('--cacert', dest='cacert', default=CACERT,
                             help='set location of ca certificate, default: %default')
    parser.add_option_group(input_options)

    output_options = OptionGroup(parser, 'Output options')
    output_options.add_option('--output', dest='output', help='save to file')
    output_options.add_option('--text', dest='text', action='store_true', default=False,
                              help='print request or certificate')
    parser.add_option_group(output_options)

    info_options = OptionGroup(parser, 'Info options')
    info_options.add_option('--issuer', dest='issuer', action='store_true', default=False,
                            help='get issuer of certificate')
    info_options.add_option('--subject', dest='subject', action='store_true', default=False,
                            help='get subject of certificate')
    info_options.add_option('--extension', dest='extension', help='get extension of certificate')
    parser.add_option_group(info_options)

    options, args = parser.parse_args()
    if options.genkey and options.bits:
        make_private_key(options.bits, options.output)
    elif options.genreq and options.pkey:
        check_selinux_context(options.secontext)
        make_request(options.pkey, options.user, options.secontext, options.critical, options.output, options.text)
    elif options.gencert and options.request:
        check_permissions()
        make_certificate(options.request, options.cakey, options.cacert,
                         options.output, options.signature, options.text)
    elif options.sign and options.pkey and options.certificate and options.request:
        sign(options.pkey, options.certificate, options.request)
    elif options.verify and options.cacert and options.certificate and options.request:
        verify(options.certificate, options.cacert, options.request, options.output)
    elif options.issuer and options.certificate:
        get_issuer(options.certificate)
    elif options.subject and options.certificate:
        get_subject(options.certificate)
    elif options.text and options.certificate:
        print_certificate(options.certificate)
    elif options.certificate and options.extension:
        print(get_extension(options.certificate, options.extension))
    elif options.text and options.request:
        print_request(options.request)
    else:
        parser.print_help()