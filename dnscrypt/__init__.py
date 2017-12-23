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


"""dnspython compatible DNSCrypt library"""

import time
import logging
import socket
import struct

import dns.flags
from dns.inet import is_multicast
import dns.name
import dns.message
import dns.query
import dns.rdatatype
import dns.rdataclass
import dns.resolver
from dns._compat import string_types

from nacl.public import PrivateKey, PublicKey, Box
from nacl.signing import VerifyKey
import nacl.utils
import nacl.exceptions

DNSCRYPT_MINIMUM_SIZE = 256
DNSCRYPT_MODULO_SIZE = 64
DNSCRYPT_NONCE_SIZE = 12
DNSCRYPT_RESOLVER_MAGIC = 'r6fnvWj8'
DNSCRYPT_CERT_MAGIC = 'DNSC'


class Resolver(object):
    def __init__(self, address, provider_name, provider_pk, private_key=None,
                 port=53, timeout=5):
        self.address = address
        self.port = port
        self.publickey = None
        self.serial = None
        self.tcp_only = False
        self.timeout = timeout

        if not private_key:
            self.private = PrivateKey.generate()
            logging.info('Private Key: %s' %
                self.private.encode(nacl.encoding.HexEncoder))  # noqa
            logging.info('Public Key : %s' %
                self.private.public_key.encode(nacl.encoding.HexEncoder))  # noqa
        else:
            self.private = PrivateKey(private_key, nacl.encoding.HexEncoder)

        try:
            vk = VerifyKey(provider_pk.replace(':', '').lower(),
                           nacl.encoding.HexEncoder)
        except TypeError:
            # assume this means we have an address instead of a public key
            try:
                answer = dns.resolver.query(
                    provider_pk, rdtype=dns.rdatatype.TXT)
                fp = ''.join(answer.response.answer[0][0].strings)
                vk = VerifyKey(fp.replace(':', '').lower(),
                               nacl.encoding.HexEncoder)
            except:
                raise TypeError('No valid public key for %s' % provider_name)

        question = dns.message.make_query(
            provider_name, rdtype=dns.rdatatype.TXT)
        try:
            answer = dns.query.udp(question, self.address, port=self.port,
                                   timeout=self.timeout)
            if answer.flags & dns.flags.TC:
                answer = dns.query.tcp(question, self.address, port=self.port,
                                       timeout=self.timeout)
        except dns.exception.Timeout:
            logging.debug('Failed over UDP, trying TCP')
            self.tcp_only = True
            answer = dns.query.tcp(question, self.address, port=self.port,
                                   timeout=self.timeout)

        now = time.time()
        for possible in answer.answer[0]:
            possible = ''.join(possible.strings)
            logging.debug('Possible cert %s' % possible.encode('hex'))
            (magic, es_version, minor_version, signed) = \
                struct.unpack('!4sHH%ss' % (len(possible) - 8), possible)

            logging.debug('Crytpo version %s' % es_version)

            if magic != DNSCRYPT_CERT_MAGIC:
                logging.warn('Bad certificate magic: %s' % magic)
                continue

            if es_version != 1:
                logging.warn('Not using es_version 1')
                continue

            try:
                data = vk.verify(signed)
            except nacl.exceptions.BadSignatureError:
                logging.warn('Signature did not match')
                continue

            (pk, client_magic, serial, start, expire, _) = \
                struct.unpack('!32s8sIII%ss' % (len(data) - 52), data)

            if start > now:
                logging.warn('Certification not yet valid: %s' % start)
                continue

            if expire < now:
                logging.warn('Certificate expired %s' % expire)
                continue

            if self.serial is None or serial > self.serial:
                self.publickey = PublicKey(pk)
                self.serial = serial
                self.client_magic = client_magic

        if not self.publickey:
            raise TypeError('No valid certificate found for %s:%s (%s)' %
                            source, source_port, provider_name)

        logging.info('Selected certificate %s' % self.serial)
        self.__secretbox = Box(self.private, self.publickey)

    def query(self, qname, rdtype=1, rdclass=1, tcp=False, source=None,
              raise_on_no_answer=True, source_port=0):
        if isinstance(qname, string_types):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, string_types):
            rdtype = dns.rdatatype.from_text(rdtype)
        if dns.rdatatype.is_metatype(rdtype):
            raise dns.resolver.NoMetaqueries
        if isinstance(rdclass, string_types):
            rdclass = dns.rdataclass.from_text(rdclass)
        if dns.rdataclass.is_metaclass(rdclass):
            raise dns.resolver.NoMetaqueries

        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)

        query = dns.message.make_query(qname, rdtype=rdtype, rdclass=rdclass)
        try:
            tcp_attempt = False
            if tcp or self.tcp_only:
                tcp_attempt = True
                response = self.tcp(query, timeout=self.timeout, source=source,
                                    source_port=source_port)
            else:
                response = self.udp(query, timeout=self.timeout, source=source,
                                    source_port=source_port)
                if response.flags & dns.flags.TC:
                    tcp_attempt = True
                    response = self.tcp(query, timeout=self.timeout,
                                        source=source, source_port=source_port)
        except (socket.error, dns.exception.Timeout, dns.exception.FormError,
                dns.query.UnexpectedSource, EOFError) as ex:
                raise dns.resolver.NoNameservers(
                    request=query,
                    errors=[(self.address, tcp_attempt, self.port, ex,
                             response)])

        rcode = response.rcode()
        if rcode == dns.rcode.YXDOMAIN:
            raise dns.resolver.YXDOMAIN()
        elif rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses=[response])

        return dns.resolver.Answer(qname, rdtype, rdclass, response,
                                   raise_on_no_answer)

    def __encrypt_query(self, query):
        message = query.to_wire()

        # Technically for TCP there is no requirement for DNSCRYPT_MINIMUM_SIZE
        # but it simplified my logic so fuck it
        if len(message) < DNSCRYPT_MINIMUM_SIZE:
            padding = DNSCRYPT_MINIMUM_SIZE - len(message)
        elif not len(message) % DNSCRYPT_MODULO_SIZE:
            padding = len(message) % DNSCRYPT_MODULO_SIZE
        else:
            padding = 0

        if padding:
            message += '\x80' + '\x00' * padding

        nonce = nacl.utils.random(DNSCRYPT_NONCE_SIZE)
        encrypted = self.__secretbox.encrypt(
            message, nonce + '\x00' * DNSCRYPT_NONCE_SIZE)
        # Remove the server nonce
        encrypted = encrypted[0:12] + encrypted[24:]
        return self.client_magic + self.private.public_key.encode() + encrypted

    def __decrypt_response(self, wire, one_rr_per_rrset):
        (magic, nonce, data) = struct.unpack('!8s24s%ss' %
                                             (len(wire) - 32), wire)
        if magic != DNSCRYPT_RESOLVER_MAGIC:
            raise TypeError('This does not appear to be DNSCrypt')

        payload = self.__secretbox.decrypt(data, nonce)
        # we could try to find the padding, but easier just to ignore it
        return dns.message.from_wire(payload, ignore_trailing=True,
                                     one_rr_per_rrset=one_rr_per_rrset)

    def tcp(self, query, timeout=None, af=None, source=None, source_port=0,
            one_rr_per_rrset=False):
        wire = self.__encrypt_query(query)
        (af, destination, source) = dns.query._destination_and_source(
            af, self.address, self.port, source, source_port)
        s = dns.query.socket_factory(af, socket.SOCK_STREAM)
        begin_time = None
        try:
            expiration = dns.query._compute_expiration(timeout)
            s.setblocking(0)
            begin_time = time.time()
            if source is not None:
                s.bind(source)
            dns.query._connect(s, destination)
            l = len(wire)
            tcpmsg = struct.pack('!H', l) + wire
            dns.query._net_write(s, tcpmsg, expiration)
            ldata = dns.query._net_read(s, 2, expiration)
            (l, ) = struct.unpacket('!H', ldata)
            wire = dns.query._net_read(s, l, expiration)
        finally:
            if begin_time is None:
                response_time = 0
            else:
                response_time = time.time() - begin_time
            s.close()

        r = self.__decrypt_response(wire, one_rr_per_rrset)
        r.time = response_time
        if not query.is_response(r):
            raise dns.query.BadResponse
        return r

    def udp(self, query, timeout=None, af=None, source=None, source_port=0,
            ignore_unexpected=False, one_rr_per_rrset=False):
        wire = self.__encrypt_query(query)
        (af, destination, source) = dns.query._destination_and_source(
            af, self.address, self.port, source, source_port)

        s = dns.query.socket_factory(af, socket.SOCK_DGRAM)
        begin_time = None
        try:
            expiration = dns.query._compute_expiration(timeout)
            s.setblocking(0)
            if source is not None:
                print source
                s.bind(source)
            dns.query._wait_for_writable(s, expiration)
            begin_time = time.time()
            s.sendto(wire, destination)
            while 1:
                dns.query._wait_for_readable(s, expiration)
                (wire, from_address) = s. recvfrom(65535)
                if dns.query._addresses_equal(af, from_address, destination) \
                   or (is_multicast(self.address) and
                       from_address[1:] == destination[1:]):
                    break
                if not ignore_unexpected:
                    raise dns.query.UnexpectedSource(
                        'got a response from %s instead of %s' % (from_address,
                                                                  destination))
        finally:
            if begin_time is None:
                response_time = 0
            else:
                response_time = time.time() - begin_time
            s.close()

        r = self.__decrypt_response(wire, one_rr_per_rrset)
        r.time = response_time
        if not query.is_response(r):
            raise dns.query.BadResponse
        return r


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    Resolver('208.67.222.222', '2.dnscrypt-cert.opendns.com', 'B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79').query('google.com')
    Resolver('45.76.35.212', '2.dnscrypt-cert.ns0.dnscrypt.nl', '4C84:FB8C:0511:5DFA:5F97:C5ED:0329:1370:C78A:BCD6:4E15:DD53:AB08:DE72:FB84:4ACA', port=443)
    Resolver('146.185.167.43', '2.dnscrypt-cert.securedns.eu', '2.dnscrypt-cert.securedns.eu', port=5353)
