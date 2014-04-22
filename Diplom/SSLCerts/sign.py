__author__ = 'dimv36'

from M2Crypto import BIO, SMIME, X509, Rand

ptxt = X509.load_request("dimv36.csr").as_text()


def makebuf():
    buf = BIO.MemoryBuffer(ptxt)
    return buf


def sign():
    print 'test sign & save...',
    buf = makebuf()
    s = SMIME.SMIME()
    s.load_key('private.key', 'dimv36.cert')
    p7 = s.sign(buf)
    out = BIO.openfile('clear.p7', 'w')
    buf = makebuf()
    s.write(out, p7, buf)
    out.close()

    buf = makebuf()
    p7 = s.sign(buf)
    out = BIO.openfile('opaque.p7', 'w')
    s.write(out, p7)
    out.close()
    print 'ok'


def verify():
    print 'test load & verify opaque...',
    s = SMIME.SMIME()
    x509 = X509.load_cert('dimv36.cert')
    sk = X509.X509_Stack()
    sk.push(x509)
    s.set_x509_stack(sk)
    st = X509.X509_Store()
    st.load_info('dimv36.cert')
    s.set_x509_store(st)
    p7, data = SMIME.smime_load_pkcs7('opaque.p7')
    v = s.verify(p7, data)
    if v:
        print 'ok'
    else:
        print 'not ok'

if __name__ == "__main__":
    sign()
    verify()
    # verify(sing_data)
