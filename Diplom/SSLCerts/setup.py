from distutils.core import setup

setup(
    name='pgcert',
    version='1.0',
    packages=['core'],
    url='',
    license='GPL',
    author='dimv36',
    author_email='carriingfate92@yandex.ru',
    description='pgcert is utility, that can generate SSL certificates with field SC (selinux context)',
    requires=['M2Crypto']
)
