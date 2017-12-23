##################
dnspython-dnscrypt
##################

This library is designed to make using DNSCrypt in Python easy and compatible
with dnspython_.  It provides a ``dns.resolver.Resolver``-style interface which
mixes-in the ``dns.query.udp`` and ``dns.query.tcp`` functions.

>>> import dnscrypt
>>> r = dnscrypt.Resolver('208.67.222.222', '2.dnscrypt-cert.opendns.com',
... 'B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79',
... port=53, timeout=5)
>>> print r.query('www.google.com')
<dns.resolver.Answer object at 0x103b6f450>
>>> import dns.message
>>> r.udp(dns.message.make_query('google.com', 'A'))
<DNS message, ID 16075>

Class Methods
=============

``__init__(self, address, provider_name, provider_pk, private_key=None, port=53, timeout=5)``
---------------------------------------------------------------------------------------------

address
    The IP address of the DNSCrypt resolver
port
    The port to use for communication with the DNSCrypt resolver
provider_name
    The provider name for the DNSCrypt resolver.  Takes the format ``<version>.dnscrypt-cert.<zone>``.
provider_pk
    The provider's hex-encoded public key or DNS hostname where to retreive the public key
private_key
    A hex-encoded private key if you want to reuse a key you already have.  Otherwise,
    a new key will be generated for each Resolver instance.
timeout
    Timeout in seconds for DNS lookups


``address``, ``provider_name``, and ``provider_pk`` are required.  All other
arguments are optional.

``query(qname, rdtype=1, rdclass=1, tcp=False, source=None, raise_on_no_answer=True, source_port=0)``
-----------------------------------------------------------------------------------------------------

Analogous to dns.resolver.Resolver.query_ for dnspython_.

``tcp(self, query, timeout=None, af=None, source=None, source_port=0, one_rr_per_rrset=False)``
-----------------------------------------------------------------------------------------------

Analogous to dns.query.tcp_ for dnspython_.  There is no ``where`` argument,
but is otherwise identical in function/form.

``udp(self, query, timeout=None, af=None, source=None, source_port=0, ignore_unexpected=False, one_rr_per_rrset=False)``
------------------------------------------------------------------------------------------------------------------------

Analogous to dns.query.udp_ for dnspython_.  There is no ``where`` argument,
but is otherwise identical in function/form.

Differences from dnspython
==========================

The biggest thing is that this is a very basic implementation of
``dns.resolver.Resolver``.  While it's designed to look/feel the same, it is not a
drop in replacement. (e.g. I did not implement the
``use_tsig``/``use_edns``/``set_flags`` functions, instead use
``dns.message.Message`` and ``dnscrypt.resolver.tcp`` or
``dnscrypt.resolver.udp``.)

.. _dnspython: http://www.dnspython.org
.. _dns.resolver.Resolver.query: http://www.dnspython.org/docs/1.15.0/dns.resolver.Resolver-class.html#query
.. _dns.query.tcp: http://www.dnspython.org/docs/1.15.0/dns.query-module.html#tcp
.. _dns.query.udp: http://www.dnspython.org/docs/1.15.0/dns.query-module.html#udp
