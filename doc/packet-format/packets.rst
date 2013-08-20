=======================================
Proposed format in NDN packet structure
=======================================

Change highlights
+++++++++++++++++

General
-------

Common packet header, so it is trivial to distinguish "NDN" packet from any other packet, and which provides ability for backward/forward compatibility.

Interest
--------

1. New ``NackType`` field

2. Interest selectors are grouped under ``Selectors`` field and separated from ``Name``, ``Nonce``, ``Scope``, ``NackType``, and ``Lifetime`` fields.

Data
----

1. Signature block moved to the end of the packet.

2. Removing confusing ``SignedInfo`` component.

3. Instead of ``SignedInfo``, meta information describing content of the data packet (type, time it was generated, freshness, final block ID, and others if any) is moved to under ``Content`` section.

4. ``PublisherPublicKeyDigest`` and ``ExtOpt`` completely eliminated

5. ``KeyLocator`` is simplified (only name can be used) and moved under ``Signature`` block

6. ``Signature`` is completely redesigned:

  - ``DigestAlgorithm`` is completely eliminated

  - depending on the signature algorithm used, it would contain ``SignatureEmtpy``, ``SignatureSha256``, ``SignatureSha256WithRsa``, or ``SignatureSha256WithRsaAndMerkley`` TLV

  - ``Witness`` is moved under ``SignatureSha256WithRsaAndMerkley`` TLV, since it is relevant to only this type of signature

This document describes a proposed modification to NDN packet structure.  The document does not specify specific wire format, but it is assumed that a TLV-like format (e.g., Cisco proposal) is used for each of the presented field, with exception of the ``CommonHeader`` field.


NDN Packet
++++++++++

::

        Packet ::= CommonHeader
                   (Interest | Data)

Common NDN Header
+++++++++++++++++

::

	CommonHeader ::= Version Length

- ``Version``: to provide wire-format compatibility with future (if any) and existing format.
  For example, if version is 2 bytes, 0x01D2 and 0x0482 would refer to CCNx Interest and Data packets, other values can refer to new TLV format.


Interest
++++++++

The objective of the new format is to optimize encoding/decoding operations.

::

	Interest ::= Name
                     Nonce
	     	     Scope?
                     NackType?
		     Lifetime?
	     	     Selectors?

Specific order of fields TBD.

Name
++++

::

	Name ::= (NameComponent)*


Selectors
+++++++++

::

	Selectors ::= (Selector)*

	Selector ::= MinSuffixComponents | 
                     MaxSuffixComponents | 
                     Publisher | 
                     Exclude | 
                     ChildSelector | 
                     AnswerOriginKind

Exclude
+++++++

::

	Exclude ::= (ExcludeComponent)*

        ExcludeComponent ::= NameComponent AnyNameComponent? |
                             AnyNameComponent


Data
++++

::

	Data ::= Name
                 Content
                 Signature


Content
+++++++

::

	Content ::= Type?
                    Timestamp?
                    Freshness?
                    FinalBlockID?
		    ContentBlob

Signature
+++++++++

::

	Signature ::= SignatureEmtpy |
                      SignatureSha256 |
                      SignatureSha256WithRsa |
                      SignatureSha256WithRsaAndMerkley |
                      (other types of signatures)

        SignatureEmtpy ::= (empty)

        SignatureSha256 ::= SignatureBits

        SigatureSha256WithRsa ::= SignatureBits KeyLocator

        SignatureSha256WithRsaAndMerkley ::= SignatureBits KeyLocator Witness

KeyLocator
++++++++++

::

	KeyLocator ::= CertName
		       
	CertName ::= Name

