# /usr/bin/env python2
#
# Copyright (C) 2017 Brian Hartvigsen
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

from distutils.core import setup

version = '1.0.1'

setup(name='dnscrypt',
      version=version,
      maintainer='Brian Hartvigsen',
      maintainer_email='bhartvigsen@opendns.com',
      description='dnspython compatible DNSCrypt Resolver',
      url="https://github.com/tresni/dnspython-dnscrypt",
      long_description=open('README.rst').read(),
      license='ISC',
      packages=['dnscrypt', ],
      install_requires=['dnspython == 1.15.0',
                        'PyNaCl == 1.2.1'],
      classifiers=[
          "Programming Language :: Python :: 2",
          "Programming Language :: Python :: 2.7"
      ])
