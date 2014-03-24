#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from M2Crypto import RSA, X509, EVP, ASN1
from subprocess import check_output
from datetime import datetime
from optparse import OptionParser
from os import path, getuid
from time import time
__author__ = 'dimv36'


DEFAULT_FIELDS = {'C': 'ru',
                  'ST': 'msk',
                  'L': 'msk',
                  'O': 'mephi',
                  'OU': 'kaf36',
                  'CN': check_output("whoami", shell=True)[0].split('\n')[0]}
DEFAULT_PASSWORD = '123456'


def password(*args, **kwargs):
    return DEFAULT_PASSWORD


def check_permissions():
    if getuid() != 0:
        print('Пожалуйста, зайдите за пользователя `root` и повторите команду')
        exit(1)


def make_private_key(bits, output):
    rsa_key = RSA.gen_key(bits, 65537, callback=password)
    if not output:
        output = path.abspath(path.curdir) + '/mykey.pem'
    rsa_key.save_key(output, None)
    return 'Сертификат сохранён в %s' % output


def make_request(private_key_file, username, context_string, output):
    private_key = EVP.load_key(private_key_file, callback=password)
    if not private_key:
        raise ValueError, 'Неверный путь к приватному ключу'
    request = X509.Request()
    request.set_pubkey(private_key)
    request.set_version(3)
    name = X509.X509_Name()
    name.C = DEFAULT_FIELDS['C']
    name.ST = DEFAULT_FIELDS['ST']
    name.L = DEFAULT_FIELDS['L']
    name.O = DEFAULT_FIELDS['O']
    name.OU = DEFAULT_FIELDS['OU']
    name.CN = username
    if context_string:
        context = context_string
    else:
        context = check_output('id -Z', shell=True).split('\n')[0]
    if not context:
        raise ValueError, 'Команда`id -Z` возвратила ошибку'
    name.SC = context
    request.set_subject_name(name)
    request.sign(private_key, 'sha1')
    if not output:
        output = path.abspath(path.curdir) + '/%s.csr' % DEFAULT_FIELDS['CN']
    request.save_pem(output)
    return 'Запрос на подпись сертификата сохранён в %s' % output


def make_certificate(request_file, ca_private_key_file, ca_certificate_file, output):
    request = X509.load_request(request_file)
    public_key = request.get_pubkey()
    if not request.verify(public_key):
        raise ValueError, 'Ошибка при проверке запроса на подпись сертификата'
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
    certificate.add_ext(X509.new_extension('basicConstraints', 'CA:FALSE', 1))
    if not output:
        output = path.abspath(path.curdir) + '/%s.cert' % DEFAULT_FIELDS['CN']
    certificate.sign(ca_private_key, 'sha1')
    certificate.save(output)
    return 'Сертифкат сохранён в %s' % output


def verify_certificate(certificate_file, ca_certificate):
    certificate = X509.load_cert(certificate_file)
    if not certificate:
        raise ValueError, 'Ошибка при загрузке сертифката'
    ca_certificate = X509.load_cert(ca_certificate)
    ca_public_key = ca_certificate.get_pubkey()
    if not ca_certificate:
        raise ValueError, 'Ошибка при загрузке приватного ключа пользователя'
    if certificate.verify(ca_public_key):
        return 'Сертифкат достоверный'
    else:
        pass
    return 'Сертифкат не достоверный'


def print_certificate(certificate_file_path):
    if not path.exists(certificate_file_path):
        raise ValueError, 'Путь к сертифкату %s не существует' % certificate_file_path
    certificate = X509.load_cert(certificate_file_path)
    return certificate.as_text()


def print_request(request_file_path):
    if not path.exists(request_file_path):
        raise ValueError, 'Путь к запросу на подпись сертифката %s не существует' % request_file_path
    request = X509.load_request(request_file_path)
    return request.as_text()


def make_ca(bits, cakey_file_path, cacert_file_path):
    make_private_key(bits, cakey_file_path)
    private_key = EVP.load_key(cakey_file_path, callback=password)
    if not private_key:
        raise ValueError, 'Ошибка при загрзке приватного ключа удостоверяющего центра'
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
    certificate.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE', 1))
    certificate.sign(private_key, 'sha1')
    certificate.save(cacert_file_path)
    return 'Сертифкат сохранён %s' % cacert_file_path


if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [--genrsa | --genreq | --gencert | --makeca | --text] options",
                          add_help_option=True,
                          description="Pgcert - утилита, позволяющая генерировать сертификаты X509 с полем SC, "
                                      "в котором хранится текущий контекст пользователя, а также выполнять различные "
                                      "операции с ними.")
    parser.add_option("--genrsa", dest="genrsa", action="store_true", default=False,
                      help="Создать приватный RSA-ключ по количеству bits")
    parser.add_option("--genreq", dest="genreq", action="store_true", default=False,
                      help="Создать запрос на подпись сертификата по приватному ключу pkey")
    parser.add_option("--gencert", dest="gencert", action="store_true", default=False,
                      help="Создать сертификат пользователя по request")
    parser.add_option("--makeca", dest="makeca", action="store_true", default=False,
                      help="Развернуть удостоверяющий центр")
    parser.add_option("--text", dest="print_pem", action="store_true", default=False,
                      help="Распечатать сертификат или запрос на подпись сертификата")
    parser.add_option("--verify", dest="verify", action="store_true", default=False,
                      help="Проверить, выдан ли сертификат пользователя данным удостоверяющим центром")
    parser.add_option("--user", dest="user", default=DEFAULT_FIELDS['CN'],
                      help="Добавить имя пользователя в запрос на подпись сертификата (опционально)")
    parser.add_option("--context", dest="context", default=None,
                      help="Добавить контекст пользователя в запрос на подпись сертфиката (опционально)")
    parser.add_option("--bits", dest="bits", type="int", default="2048",
                      help="Длина приватного ключа (по умолчанию %default)")
    parser.add_option("--request", dest="request", help="Путь к файлу запроса на подпись сертификата")
    parser.add_option("--cakey", dest="cakey", default="/etc/pki/CA/private/cakey.pem", type="string",
                      help="Путь до приватного ключа удостоверяющего центра (по умолчанию %default)")
    parser.add_option("--cacert", dest="cacert", default="/etc/pki/CA/cacert.pem", type="string",
                      help="Путь к сертификату удостоверяющего центра (по умолчанию %default)")
    parser.add_option("--pkey", dest="pkey", help="Путь к приватному ключу пользователя")
    parser.add_option("--cert", dest="certificate", help="Путь к сертифкату")
    parser.add_option("--output", type="string", dest="output", help="Путь к файлу вывода")
    options, args = parser.parse_args()
    user = options.user
    context = options.context
    bits = options.bits
    request = options.request
    cakey = options.cakey
    cacert = options.cacert
    pkey = options.pkey
    certificate = options.certificate
    output = options.output
    if options.genrsa and options.bits:
        print(make_private_key(bits, output))
    elif options.genreq and options.pkey:
        print(make_request(pkey, user, context, output))
    elif options.gencert and options.request:
        check_permissions()
        print(make_certificate(request, cakey, cacert, output))
    elif options.verify and options.certificate and options.cacert:
        print(verify_certificate(certificate, cacert))
    elif options.print_pem and options.certificate:
        print(print_certificate(certificate))
    elif options.print_pem and options.request:
        print(print_request(request))
    elif options.makeca:
        check_permissions()
        print(make_ca(bits, cakey, cacert))
    else:
        parser.print_help()