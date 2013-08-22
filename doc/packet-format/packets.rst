=======================================
Proposed format in NDN packet structure
=======================================

Change highlights
+++++++++++++++++

1. General

    Common packet header, so it is trivial to distinguish "NDN" packet from any other packet, and which provides ability for backward/forward compatibility.

2. Interest

    - New ``NackType`` field

    - Interest selectors are grouped under ``Selectors`` field and separated from ``Name``, ``Nonce``, ``Scope``, ``NackType``, and ``Lifetime`` fields.

2. Data

    - Signature block moved to the end of the packet.
  
    - Removing confusing ``SignedInfo`` component.
   
    - Instead of ``SignedInfo``, meta information describing content of the data packet (type, time it was generated, freshness, final block ID, and others if any) is moved to under ``Content`` section.
    
    - ``PublisherPublicKeyDigest`` and ``ExtOpt`` completely eliminated
    
    - ``KeyLocator`` is simplified (only name can be used) and moved under ``Signature`` block
    
    - ``Signature`` is completely redesigned:
    
      - ``DigestAlgorithm`` is completely eliminated
    
      - depending on the signature algorithm used, it would contain ``SignatureEmtpy``, ``SignatureSha256``, ``SignatureSha256WithRsa``, or ``SignatureSha256WithRsaAndMerkle`` TLV
    
      - ``Witness`` is moved under ``SignatureSha256WithRsaAndMerkle`` TLV, since it is relevant to only this type of signature

This document describes a proposed modification to NDN packet structure.
The document does not specify specific wire format, but it is assumed that a TLV-like format (e.g., Cisco proposal) is used for each of the presented field, with exception of the ``CommonHeader`` field.

NDN packet structure definitions
++++++++++++++++++++++++++++++++

::

        Packet ::= CommonHeader
                   (Interest | Data)

Common NDN Header
-----------------

::

	CommonHeader ::= Version

- ``Version``: to provide wire-format compatibility with future (if any) and existing format.
  For example, if version is 2 bytes, 0x01D2 and 0x0482 would refer to CCNx Interest and Data packets, other values can refer to new TLV format.

Name
----

::

	Name ::= (NameComponent)*
	
	NameComponent ::= GenericComponent |
	                  SequenceNumber |
			  Signature |
			  (other types of name componets)

``Name`` TLV represents a hierarchical name for NDN Data packet. 
It simply contains a sequence of ``NameComponent``. ``NameComponent`` represents a set of TLVs, of which each corresponds to a specific type of name component, for example, ``GenericComponent``, ``SequenceNumber``, ``Signature``, and etc. (the formal type name are TBD). 
The value of each ``NameComponent`` TLV would contains a sequence of zero or more bytes. 
There are no restrictions on what byte sequences may be used.


Interest
--------

The objective of the new format is to optimize encoding/decoding operations.

::

	Interest ::= Name
                     Nonce
	     	     Scope?
                     NackType?
		     Lifetime?
	     	     Selectors?

Specific order of fields TBD.

Nonce
^^^^^

The value of ``Nonce`` TLV is a randomly-genenerated byte string that is used to detect and discard duplicate Interest messages. 
Applications generally do not need to generate or check ``Nonce``. 
Note that ``Nonce`` is not the only basis for detecting and discarding duplicate Interest messages that arrive at a node, but can be used to improve the efficiency of the detection.

``Nonce`` is the other required field in Interest message.

Scope
^^^^^

``Scope`` limits where the Interest may propagate. 
Scope 0 prevents propagation beyond the local NDN daemon (even to other applications on the same host). 
Scope 1 limits propagation to the applications on the originating host. 
Scope 2 limits propagation to no further than the next host.
Other values are not defined, and will cause the Interest message to be dropped. 
If ``Scope`` is missing, there are no limits on Interest propagating.

Note that this is not a hop count - the value is not decremented as the Interest is forwarded.

NackType
^^^^^^^^

``NackType`` indicates whether the Interest message is a normal Interest or negative notification to routers. 

Lifetime
^^^^^^^^

``Lifetime`` indicates the time remaining before the interest times out. 
The value is encoded as an unsigned big-endian integer. 
The time unit is the same as used for the ``Timestamp`` in ``Content``, milisecond. 
The timeout is relative to the arrival time of the Interest at the current node.

If ``Lifetime`` element is omitted, the value of 4 seconds is used. 
The missing element may be added before forwarding.

It is the application that chooses the value for ``Lifetime``.


Selectors
---------

::

	Selectors ::= (Selector)*

	Selector ::= MinSuffixComponents | 
                     MaxSuffixComponents | 
                     Publisher | 
                     Exclude | 
                     ChildSelector | 
                     AnswerOriginKind |
		     (other types of selectors)

Selectors are used to advise the selection of what to send when there are multiple Data that match. 
``Selectors`` contains a sequence of ``Selector``. ``Selector`` represents a set of TLVs, of which each corresponds to a specific type of selector, for instance, ``MinSuffixComponents``, ``MaxSuffixComponents``, ``Publisher``, ``Exclude``, ``ChildSelector``, ``AnswerOriginKind``, and etc.

MinSuffixComponents, MaxSuffixComponents
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A client may need to say that the Data it is seeking has a known range of legitimate name component counts. 
To encode this there are two selectors, named ``MinSuffixComponents`` and ``MaxSuffixComponents``, that specify these limits. 
These refer to the number of name components beyond those in ``Name``. 
The default value for ``MinSuffixComponents`` is 0 and for ``MaxSuffixComponents`` is effectively infinite. 
Often only one of these will be needed to get the desired effect.

Publisher
^^^^^^^^^

::

	Publisher ::= CertName |
	              (other types of KeyLocators)

	CertName ::= Name

A client may need to say that the requested Data must be signed by a particular signer. 
``Publisher`` selector is used to encode this restriction. 
A Data can be selected only if the value of its ``Keylocator`` is the same as the value of ``Publisher`` in the Interest.

Original NDN wire format uses ``PublisherPublicKeyDigest`` instead of ``Publisher``. 
For the reason why ``PublisherPublicKeyDigest`` is replaced by ``Publisher``, see our discussion in the section of Data.

Exclude
^^^^^^^

::

	Exclude ::= (ExcludeComponent)*

        ExcludeComponent ::= AnyNameComponent |
	                     NameComponent AnyNameComponent? 
                             

``Exclude`` embodies a description of name components that should not appear as a continuation of ``Name`` in the response to the interest. 
``Exclude`` contains a sequence of ``ExcludeComponent``.
The ``NameComponent`` in the sequence of ``ExcludeComponent`` must occur in strictly increasing order according to the canonical NDN ordering.

ChildSelector
^^^^^^^^^^^^^

Often a given Interest will match more than one Data. 
The ChildSelector provides a way of expressing a preference for which of these should be returned. 
If the value is 0, the leftmost child is preferred. 
If 1, the rightmost child is preferred. 
Here leftmost and rightmost refer to the least and greatest components according to the canonical NDN ordering.
This ordering is only done at the level of the name hierarchy one past the ``Name``.

The original usage of ``ChildSelector`` is preserved in this proposed format.

AnswerOriginKind
^^^^^^^^^^^^^^^^

``AnswerOriginKind`` encodes several bitfields that alter the usual response to Interest. 
There is a do-not-answer-from-content-store bit, which also implies a passive bit. 
There will eventually need to be some security aspects to this, limiting it by scope and/or by interest signing, but we are choosing to ignore these for now.
There is also utility in the passive bit alone - it means do not generate any newly-signed content in response to this interest. 

The original usage of ``AnswerOriginKind`` is preserved in this proposed format.

Data
----

::

	Data ::= Name
                 Content
                 Signature

In this proposed format, ``Data`` contains three TLVs: ``Name``, a complex ``Content`` and a complex ``Signature``.
We removed ``SignedInfo`` from ``Data``, because ``SignedInfo`` in the original format was abused as a kitchen sink.
Elements related to content (such as ``Type``, ``Timestamp``, ``Freshness``, ``FinalBlockID``) are moved to the new ``Content``.
The element ``KeyLocator`` is moved to the new ``Signature``.
``PublisherPublicKeyDigest`` and ``ExtOpt`` are removed.

The ``SignatureBits`` in ``Signature`` covers only ``Name`` and ``Content``.
Note that ``KeyLocator`` is not signed in this proposed format, but the removal of ``KeyLocator`` from the signed blob does not compromise the security of NDN,
because the validity of ``KeyLocator`` does not rely on the signature of the packet.
If ``KeyLocator`` was tampered, then either its corresponding certificate is not trusted by validator or the corresponding public key cannot verify the signature.

The same reason also applies to ``PublisherPublicKeyDigest``, thus a signed ``PublisherPublicKeyDigest`` does not enhance the security of NDN.
Another reason for the existence of ``PublisherPublicKeyDigest`` in the original format of ``Data`` is selection among multiple Data that match.
We consider such a usage of ``PublisherPublicKeyDigest`` is not very useful:

1.  It requires one to acquire the valid public key before sending Interest out.
2.  It may require publishers to maintain their public keys and certificates by their public key digests instead of names.
3.  If one can specify the expected ``KeyLocator`` in the Interest (as the ``Publisher`` in this proposed format does), Data selection is still feasible.

As result, we removed ``PublisherPublicKeyDigest`` from this proposed format.

We removed ``ExtOpt`` because TLV format can easily support extension, so there are no needs of keeping ``ExtOpt`` any more.

Content
-------

::

	Content ::= Type?
                    Timestamp?
                    Freshness?
                    FinalBlockID?
		    ContentBlob

The only required element is ``ContentBlob`` which is a sequnce of byte and is opaque to the protocol.

Type
^^^^

The primitive type of the ``ContentBlob``. This is encoded as a 3-byte BLOB; when viewed using a base64Binary encoding, the encoded value has some mnemonic value.

Timestamp
^^^^^^^^^

``Timestamp`` indicates the time when the Data packet is generated. 
It is expressed in units of miliseconds since the start of Unix time.
``Lifetime`` in ``Interests`` and ``Freshness`` in ``Content`` are expressed in the same format as ``Timestamp``.

Freshness
^^^^^^^^^

``Freshness`` is a only suggestion to a node about how long it should wait after the arrival of this ContentObject before marking it as stale. 


FinalBlockID
^^^^^^^^^^^^

``FinalBlockID`` indicates the identifier of the final block in a sequence of fragments. 
It should be present in the final block itself, and may also be present in other fragments to provide advanced warning of the end to consumers. 
The value here should be equal to the last explicit ``NameComponent`` of the final block.

The original usage of ``FinalBlockID`` is preserved in this format.

Signature
---------

::

	Signature ::= SignatureEmtpy |
                      DigestSha256 |
                      SignatureSha256WithRsa |
                      SignatureSha256WithRsaAndMerkle |
                      (other types of signatures)

        SignatureEmtpy ::= (empty)

        DigestSha256 ::= DigestBits

        SigatureSha256WithRsa ::= SignatureBits KeyLocator

        SignatureSha256WithRsaAndMerkle ::= SignatureBits KeyLocator Witness

``Signature`` represents a set of signing mechanisms.
Among these mechanisms, ``SignatureEmpty`` indicates that the Data is not secured at all.
``DigestSha256`` indicates that the integerity of Data is protected by a SHA-256 digest in ``DigestSha256``.
``SignatureSha256WithRsa`` indicates that the integerity and provenace of Data is protected by a RSA signature over a SHA-256 digest of the ``Name`` and ``Content``.
``SignatureSha256WithRsaAndMerkle`` indicates that the integerity and provenance of Data is protected by a RSA signature over SHA-256-Merkle-Hash digest.

KeyLocator
^^^^^^^^^^

::

	KeyLocator ::= CertName |
	               (other types of KeyLocators)
		       
	CertName ::= Name

``KeyLocator`` indicates how to fetch the verifying public key. 
For example, one can specify the name of the certificate of the public key (by ``CertName``).
