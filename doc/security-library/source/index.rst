.. NDN_Security_Library_Technical_Document documentation master file, created by
   sphinx-quickstart on Fri Sep 27 09:53:08 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

NDN Security Library Technical Document
===================================================================

Overview
--------

The NDN Security Library is designed to provide a unified security framework for NDN application development.
The library provides four major security functionalities: signing, verification, encryption, and decryption.
For data signing, the library provided an identity-based signing mechanism (called IdentityManager), while also allowing other signing mechanisms.
For data verification, the library provided a flexible interface (called PolicyManager) via which application developers can implement their own trust models.
For data encryption/decryption, the library provided basic symmetric/asymmetric encryption/decryptions, and may include more advanced encryption methods in the future.

KeyChain
-------- 

KeyChain is the main class of the security library. 
A KeyChain object consists of three components: IdentityManager, PolicyManager, and EncryptionManager.

.. code-block:: c++

   KeyChain keychain(identityManager, policyManager, encryptionManager/*=NULL*/);

Among these components, IdentityManager manages private keys and their associated public parts (such as public keys, certificates, and identity), therefore data signing is performed through IdentityManager.
PolicyManager manages the process of verification, therefore it reflects the trust model of an application.
EncryptionManager is responsible for data encryption/decryption.
Unlike IdentityManager and PolicyManager which are required in a KeyChain object, EncryptionManager is optional. 

Keychain has a default constructor which initializes the the three components according to the operating system.

A KeyChain object is involved in data publishing and receiving.
An application, when publishing a data packet, can explicitly ask a KeyChain object to sign the data packet and publish it via an NDN Face object (which is used for NDN communication)

.. code-block:: c++

   keychain.sign(data, certificateName);
   face.send(data);

Or it can do it implicitly by associating the KeyChain object with the Face object. 

.. code-block:: c++

   face.setKeyChain(keychain);
   face.send(data);

.. code-block:: c++

   Face::send(Data& data, Name& certificateName/*=default certificate*/)
   {
     ...
     if(!data.isSigned())
       m_keyChain.sign(data, certificateName);
     /* send signed data out */
     ...
   }

When the application publishes a data packet via the Face object, the Face object will check whether the data packet has been signed. 
If the packet is not signed, the Face object will ask its associated KeyChain object to sign the data packet according to the signing inferences specified by the application.
If signing certificate name is not provided, the default key will be used to sign the data packet,
and the corresponding default certificate name will be put into the KeyLocator field of the Data packet.

Applications receive data packet through Face object as well. 
On receiving a data packet, the face object will ask the associated Keychain object to validate the data packet.

.. code-block:: c++

   m_keyChain.verifyData(data, verifiedCallback, unverifiedCallback, stepCount/* = 0 */);

``verifiedCallback`` is a callback function that will be invoked when the received data has been validated. 
``unverifiedCallback`` is a callback function that will be invoked when the Keychain object cannot validate the received data.
``stepCount`` is used to track the progress of a particular validation instance, in other word, how many levels the validation has gone through recursively.
``stepCount`` can be used to prevent infinite verification chain.
By default, ``stepCount`` is set to ``0``, and it will be automatically updated by the KeyChain object.

Packet Signing
--------------

KeyChain provide a basic signing method ``sign``.

.. code-block:: c++

   void 
   KeyChain::sign(Data& data, const Name& certificateName);

``data`` is the data packet to be signed. 
KeyChain will locate the private key corresponding to ``certificateName``, and use the private key to sign the data packet.
On return, the Signature part of ``data`` will be set, and the KeyLocator of ``data`` will be set to ``certificateName``.

.. code-block:: c++

   shared_ptr<Signature> 
   KeyChain::sign(Blob& blob, const Name& certificateName);

The ``sign`` method also accept a string of bytes (called Blob).
In this case, a Signature object will be returned directly.

The signing methods above require developers to explicitly specify the name of signing certificate.
This, however, is not always feasible.
In order to make data signing more convenient, KeyChain provides some other signing methods

.. code-block:: c++

   void 
   KeyChain::signByIdentity(Data& data, const Name& identity);
   
   shared_ptr<Signature> 
   KeyChain::signByIdentity(Blob& blob, const Name& identity);

Before we go into details about these two methods, it would be helpful to introduce several concepts of the identity-based signing mechanism.
The most important ones are: *Identity*, *Key*, and *Identity Certificate*.

Identity, Key, and Identity Certificate
+++++++++++++++++++++++++++++++++++++++

Identity refers to an NDN namespace, for example, "/ndn/ucla.edu/alice". 
The namespace is also called *Identity Name*.

The owner of this namespace, say Alice, may create a pair of private/public keys to sign/verify data under this namespace.
The key pair is named as appending a component, called *Key Identifier*, to the identity name, for example, "/ndn/ucla.edu/alice/DSK-1376698604".
"DSK" stands for "Data Signing Key", indicating that this key is used to sign and verify data packet.
"1376698604" is a sequence number which is used to identify different DSKs of the same identity.
In this example, a timestamp "1376698604" is used as a sequence number.

Due to the security and scalability consideration, the owner of the namespace may create another pair of private/public keys, called "Key Signing Key (KSK)".
This "Key Signing Key" concept is borrowed from DNSSEC.
As implied by its name, this pair of keys are used to sign and verify Data Signing Keys of the namespace.
With KSK, owner of the namespace can replace its DSK more frequently without bothering others to certify the new DSK.
Moreover, one can have multiple DSKs at the same time. 
For example, Alice may have a DSK "/ndn/ucla.edu/alice/DSK-1376698604" for the usage on her laptop,
while have another DSK "/ndn/ucla.edu/alice/DSK-1380234123" for the usage on her desktop.
As a result, one can eventually avoid private key transfer which often becomes a vulnerabitlity.

Although public keys may be fetched offline, it is more common to fetch public keys from the NDN network.
Since public keys are carried by data packets and every data packet is signed, a data packets carrying a public key becomes a certificate.
Among these data packets (or certificate), a special type of data packets is named after the key name, and carries the public key bits and some other necessary meta-information.
Such data packets are called *Identity Certificate*.
The data name is constructed via concatenating the key name inserted with a "KEY" component, a special certificate type name component "ID-CERT", and a sequence number,
for example, "/ndn/ucla.edu/KEY/alice/DSK-1376698604/ID-CERT/1376698630".
The producer of such a data packet certifies that the published public key bits corresponds the private key suggested by the data name.
Any one can issue an identity certificate, as a result, a public key may have multiple identity ceritificates issued by different producers.
The last component of certificate name, the sequence number, is used to distinguish the certificates issued for the same public key.

The "KEY" component in the identity certificate name indicates that the certificate is served by an application called "KEY", 
and the prefix before "KEY" is the routable prefix of the certificate server.

Identity-based Signing Mechanism
++++++++++++++++++++++++++++++++

The relations between identities, keys, and certificates can be summarized as: an identity refers to a name space;
a name space may be associated with multiple keys, and any one of them can represent the identity; 
a key may be associated with multiple identity certificates.

As shown by the example above, Alice may have two DSKs for identity "/ndn/ucla.edu/alice", one for her laptop and the other one for her desktop.
If Alice wants to publish a data "/ndn/ucla.edu/alice/foo.txt" from her laptop and publish a data "/ndn/ucla.edu/alice/bar.txt", 
she needs to explicitly specify corresponding certificate name in the ``sign`` method, although the two DSKs serves for the same identity.
One may wish to write an application without the awareness of a particular platform or context.
And this is what identity-based signing can help.

Identity-based signing requires that, on a particular platform, an identity must have one and only one default key, and a key must have one and only one default certificate.
Given that identity does not change from one platform to another, application developers do not have to take care of which certificate should be used.
As a result, an application only needs to call ``signByIdentity`` to sign data packet. 

.. code-block:: c++
 
   keyChain.signByIdentity(data, Name("/ndn/ucla.edu/alice"));

The KeyChain object will automatically find out the default key of the identity on the platform as well as the default certificate of the key.
After that, the KeyChain object will call the ``sign`` method to sign the data packet

.. code-block:: c++
 
   KeyChain::signByIdentity(Data& data, const Name& identity)
   {
     ...
     shared_ptr<Certificate> certificate = m_identityManager->getDefaultCertificateForIdentity(identity);
     ...
     sign(data, certificate->getName());
     ...
   } 

IdentityManager
+++++++++++++++

In KeyChain, all these keys and identity certificates and their relations to identities are managed by a member object, called *IdentityManager*. 
Now we need to talk about IdentityManager in detail.

Briefly speaking, IdentityManager manages two storages: a private storage called PrivateKeyStorage and a public storage called IdentityStorage.

.. code-block:: c++

   class IdentityManager
   {
     ...
   private:
     shared_ptr<IdentityStorage> m_publicStorage;
     shared_ptr<PrivatekeyStorage> m_privateStorage; 
   }

PrivateKeyStorage, as suggested by its name, stores private keys.
Besides that, it is also responsible of asymmetric key generation and security transform related to private keys (such as signing and decryption).
PrivateKeyStorage works as a black box, that is, no one can directly touch private keys.

IdentityStorage stores public keys and their identity certificates. 
Moreover, it stores the relations among identities, public keys, and identity certificates (such as default key and default certificate).

Note that the public part and private part of an asymmetric key pair are stored separately.
It is the responsibility of IdentityManager to keep the consistency between the public storage and private storage.

IdentityManager provides a set of methods to manage identities, keys, and certificates.
We will talk about this methods in next few sections.

Create Identity
+++++++++++++++

In order to make ``signByIdentity`` work, some identities must exist in IdentityManager. 
An identity instance can be created in an IdentityManager by calling the ``createIdentity`` method. 

.. code-block:: c++

   Name
   IdentityManager::createIdentity (const Name& identity);

An identity, however, as we discussed before, only refers to a name space,
an identity is not useful without corresponding keys and certificates. 
By calling ``createIdentity`` method, the IdentityManager will create an internal record of the identity,
generate a Key-Signing-Key pair for this identity as the default key of the identity.
The return value of ``createIdentity`` method is the name of the generated KSK.

Generate Key Pair
+++++++++++++++++

The initial key pair created for an new identity is Key-Signing-Key.
Ideally, Key-Signing-Key should be used to sign keys rather than normal data. 
One may need to create one or more Data-Signing-Key pairs.
And this can be done by calling ``generateRSAKeyPair`` method

.. code-block:: c++

   Name
   IdentityManager::generateRSAKeyPair (const Name & identity, bool ksk = false, int keySize = 2048);

``generateRSAKeyPair`` will call the private key storage to generate a pair of RSA keys,
and set them as DSK if ``ksk`` is set to false.
After that, the generated public key will be exported from the private key storage, and will be installed in IdentityManager.
The return value of ``generateRSAKeyPair`` is the name of the generated key pair.

Generate Identity Certificate
+++++++++++++++++++++++++++++

A single pair of public/private key pair is not very useful sometimes.
For example, a DSK may need an identity certificate signed by the corresponding KSK to prove itself.
And one may need to put an identity certificate name into the KeyLocator of a data packet.
For this simple use case, IdentityManager provides ``createIdentityCertificate`` method

.. code-block:: c++

   shared_ptr<IdentityCertificate>
   IdentityManager::createIdentityCertificate (const Name& certificatePrefix, 
                                               const Name& signerCertificateName, 
					       const Time& notBefore, 
					       const Time& notAfter);

``createIdentityCertificate`` will construct an unsigned identity certificate using the public key indicated by ``certificatePrefix`` which has already contains the "KEY" component, and validity information ``notBefore`` and ``notAfter``.
After that, the private key, which corresponds to the certificate with the name indicated by ``signerCertificateName``, will be used to sign the identity certificate.
The return value of ``createIdentityCertificate`` is the name of the generated identity certificate.

If the public key to be signed is managed by others, one must supply the public key bits.
And the return value of ``createIdentityCertificate`` is the generated identity certificate.
 
.. code-block:: c++

   shared_ptr<Certificate>
   IdentityManager::createIdentityCertificate (const Name& certificatePrefix,
                                               const Publickey& publickey,
                                               const Name& signerCertificateName, 
					       const Time& notBefore, 
					       const Time& notAfter);

Note that, ``createIdentityCertificate`` method can only generate the most basic identity certificate.
If developers wants to create some more complicated identity certificate (e.g., adding more subject descriptions), 
they should create the certificate as normal data packet and use other signing methods (such as ``sign`` or ``signByIdentity``).

Export Public Key
+++++++++++++++++

As we just mentioned, public key bits must be supplied when signer and signee are managed by different Identity instances. 
IdentityManager must be able to export public key bits, and ``getPublickey`` method serves this purpose.

.. code-block:: c++

   shared_ptr<Publickey>
   IdentityManager::getPublickey (const Name& keyName);


Install Identity Certificate
++++++++++++++++++++++++++++

No matter whether an identity certificate is signed within the same IdentityManager instance or not, 
the generated identity certificate (or the certificate name at least) must be installed in the IdentityManager that manages the corresponding public/private key pair.
Once the requested certificate is obtained, it can be installed via calling ``installIdentityCertificate`` method

.. code-block:: c++
   
   void
   IdentityManager::addCertificate (const IdentityCertificate& certificate);

Example
+++++++

Here is an example showing how to set identity, key, and identity certificate.

.. code-block:: c++

   IdentityManager identityManager(...); /* get a IdentityManager */

   Name alice("/ndn/ucla.edu/alice");
  
   /* create the identity and the initial KSK */
   Name aliceKskName = identityManager.createIdentity(alice);
   
   /* get the self-signed identity certificate of the KSK (the default key for now) for signing */
   shared_ptr<IdentityCertificate> aliceKskSelfSignedCert = identityManager.selfSign(aliceKskName);

   /* ask operators of "/ndn/ucla.edu/" to generate an identity certificate of the KSK, and install the certificate*/
   ... 
   identityManager.addCertificate(aliceKSKCert);

   /* generate a RSA key pair as DSK */
   Name aliceDskName = identityManager.generateRSAKeyPair(alice, false, 2048); 

   Time notBefore(...);
   Time notAfter(...);

   /* create an identity certificate for the DSK, signed by the KSK */
   shared_ptr<IdentityCertificate> aliceDSKCert = identityManager.createIdentityCertificate(aliceDskCertPrefix, aliceKskCertName, notBefore, notAfter); 

   /* install the identity certificate */
   identityManager.addCertificate(*aliceDSKCert);

   /* set the DSK and its certificate as default key and certificate of "/ndn/ucla.edu/alice" */
   identityManager.setDefaultKeyForIdentity(aliceDSKName);
   identityManager.setDefaultCertificateForKey(aliceDSKCert->getName());


Packet Verification
-------------------

When a data packet is received, ``KeyChain::verifyData`` methods will be called to validate the received data packet.

.. code-block:: c++

   void
   KeyChain::verifyData (shared_ptr<Data> data, 
                         const DataCallback & verifiedCallback, 
                         const UnverifiedCallback& unverifiedCallback,
                         int stepCount)
   {
     if(m_policyManager->requireVerify(*data))
      {
        shared_ptr<ValidationRequest> nextStep = m_policyManager->checkVerificationPolicy(data, 
                                                                                   stepCount,
                                                                                   verifiedCallback,
                                                                                   unverifiedCallback);
        if(NULL != nextStep)
          {
            /**
	     * prepare callback functions for the requested data
	     * and increase stepCount 
	     */
            ...

	    /* execuate the next step of validation */
            m_face->expressInterest(nextStep->m_interest, callbacks...);
          }
      }
    else if(m_policyManager->skipVerifyAndTrust(*data))
      return verifiedCallback(data);
    else
      return unverifiedCallback(data);
   }

As shown in the code above, ``verifyData`` method significantly rely on another member object of KeyChain, called *m_policyManager*, which is an object of *PolicyManager* class.
Let's go through ``verifyData`` method before we go into the details of PolicyManager.

The first step of ``verifyData`` is asking PolicyManager whether there is a policy that requires the received data to be verified.
If not, ``verifyData`` will double check with PolicyManager that there is a policy that explicitly take the received data packet as trusted without verification.
If so, the ``verifiedCallback`` function will be invoked, 
otherwise whether the data packet should be verified is undefined in PolicyManager and the ``unverifiedCallback`` function will be invoked.

If PolicyManager requires that the received data packet must be verified,
``verifyData`` will ask PolicyManager for the information of the next validation step, and perform the next step if it is indicated by PolicyManager. 


PolicyManager
+++++++++++++

PolicyManager is defined as an abstract class, so that application developers can make their own implementation to reflect the required trust model.

For example, if an application does not want to verify any packets (This is a bad example, and should only used in some quick demo), 
developer can implement a ``NoVerifyPolicyManager`` like this:

.. code-block:: c++
   
   bool 
   NoVerifyPolicyManager::skipVerifyAndTrust (const Data & data)
   { return true; }

   bool
   NoVerifyPolicyManager::requireVerify (const Data & data)
   { return false; }
    
   shared_ptr<ValidationRequest>
   NoVerifyPolicyManager::checkVerificationPolicy(shared_ptr<Data> data, 
                                                  const int & stepCount, 
                                                  const DataCallback& verifiedCallback,
                                                  const UnverifiedCallback& unverifiedCallback)
   { 
     verifiedCallback(data); 
     return NULL;
   }

This ``NoVerifyPolicyManager`` implementation does not require verification on any data packets and explicitly take any unverified data packets as trusted.

We can implement the PKI trust model as another example:

.. code-block:: c++
   
   bool 
   SimplePKIPolicyManager::skipVerifyAndTrust (const Data & data)
   { return false; }

   bool
   SimplePKIPolicyManager::requireVerify (const Data & data)
   { return true; }
    
   shared_ptr<ValidationRequest>
   SimplePKIPolicyManager::checkVerificationPolicy(shared_ptr<Data> data, 
                                                  const int & stepCount, 
                                                  const DataCallback& verifiedCallback,
                                                  const UnverifiedCallback& unverifiedCallback)
   { 
     ...
     if(stepCount > m_maxStep){
       unverifiedCallback(data);
       return NULL;
     }

     shared_ptr<Certificate> trustAnchor = m_trustAnchor->get(data->getKeyLocator());

     if(trustAnchor == NULL){
       DataCallback recursiveVerifiedCallback = ...;
       UnverifiedCallback recursiveUnverifiedCallback = ...;
       shared_ptr<Interest> interest = shared_ptr<Interest>(new Interest(data->getKeyLocator()));

       shared_ptr<ValidationRequest> nextStep = shared_ptr<ValidationRequest>(new ValidationRequest(interest, 
                                                                                      recursiveVerifiedCallback,
                                                                                      recursiveUnverifiedCallback,
                                                                                      retrialLimit));
       return nextStep;
     }
     else{
       if(verifySignature(data, trustAnchor->getPublicKey()){
         verifiedCallback(data);
	 return NULL;
       }
       else{
         unverifiedCallback(data);
	 return NULL;
       }
   }

This ``SimplePKIPolicyManager`` implementation requires that every data must be verified.
Before validating a data packet, ``SimplePKIPolicyManager`` check if the KeyLocator in the received data packet is one of the trust anchors.
If not, ``SimplePKIPolicyManager`` will construct a ``ValidationRequest`` for the next validation step to fetch the certificate pointed by the KeyLocator.
A part of ``ValidationRequest`` is a ``recursiveVerifiedCallback`` function which will be invoked if the requested certificate has been validated.
And when ``recursiveVerifiedCallback`` is invoked, it will invoke ``verifiedCallback`` on the received data packet.
With such a series of recursive callback functions, 
``SimplePKIPolicyManager`` can eventually construct a chain of trust from the original data packet to one of its trust anchors.


Encryption & Decryption
-----------------------

In KeyChain class, Data encryption/decryption is managed by a member ``m_encryptionManager`` which is an EncryptionManager object.
EncryptionManager provides symmetric/asymmetric encryption/decryption.
For symmetric encryption/decryption, EncryptionManager is able to generate and manage symmetric keys.
For asymmetric encryption/decryption, EncryptionManager may generate the asymmetric key pairs.
Some application may use one's identity keys (such as DSK) for encryption, therefore EncryptionManager may also have the access to the private key storage of IdentityManager.

All encryption and decryption operations are performed through two methods:

.. code-block:: c++
   
   shared_ptr<Blob> 
   Keychain::encrypt(const Name & keyName, const Blob & blob, bool sym, EncryptMode em)
   {
     return m_encryptionManager->encrypt(keyName, blob, sym, em);
   }

   shared_ptr<Blob> 
   Keychain::decrypt(const Name & keyName, const Blob & blob, bool sym, EncryptMode em)
   {
     return m_encryptionManager->decrypt(keyName, blob, sym, em);
   }
		  
``keyName`` is the name of the encryption/decryption key.
``blob`` is the data to be encrypted/decrypted.
``sym`` indicates that whether symmetric encryption is used or not.
``em`` indicates the encryption mode that will be used.										   

Certificate
-----------

Certificate in NDN Security Library is indeed a data packet.
Its format is very similar to X.509 certificate but with some NDN adaptions.

+-------------------+-----------------------+-----------------+
| X.509 Certificate | NDN Certificate       | NDN Data packet |
+===================+=======================+=================+
| Serial Number     | Data Name             | Data Name       |
+-------------------+-----------------------+-----------------+
| Validity          | Validity              | Data Content    |
+-------------------+-----------------------+                 |
| Subject           | SubjectDescryption    |                 |													    
+-------------------+-----------------------+                 |
| Subject Public    | Publickey             |                 |
| Key Info          |                       |                 |
+-------------------+-----------------------+                 |
| Extensions        | CertificateExtentsion |                 |
+-------------------+-----------------------+-----------------+
| Issuer            | KeyLocator            | Data Signature  |
+-------------------+-----------------------+                 |
| Certificate Sig   | Signature Algorithm   |                 |													      
| Algorithm         |                       |                 |
+-------------------+-----------------------+                 |		    		 
| Certificate       | Signature Bits        |                 |				      
| Signature         |                       |                 |
+-------------------+-----------------------+-----------------+

Serial number uniquely identifies an X.509 certificate, so does data name.

Validity, SubjectDescryption, Publickey, and CertificateExtentsion are DER encoded in the same way as X.509.
The encoded data are put into Content of the corresponding NDN data packet.

We adjust Issuer, Certificate Signature Algorithm, and Certificate Signature a little bit to fit into NDN Signature structure.
   
Miscellaneous
-------------

PolicyManager & Packet Signing
++++++++++++++++++++++++++++++

Although PolicyManager is most used in packet validation, it can be also used to help packet signing.
In PolicyManager, two methods are provided for this purpose: ``checkSigningPolicy`` and ``inferSigningIdentity``:

.. code-block:: c++
   
   bool 
   PolicyManager::checkSigningPolicy(const Name & dataName, const Name & certificateName);

   Name 
   PolicyManager::inferSigningIdentity(const Name & dataName);

``checkSigningPolicy`` is used to check whether the data name and the signing certificate name comply with some policies. 
An implementation of PolicyManager can always return true, if no one cares which key signs which data,
while some other implementations may wish to impose some restrictions on the outgoing data.

``inferSigningIdentity`` is used to simplify signing process, so that developers do not have to explicitly specify the signing certificates or identities in the code.
Developers can specify the signing identities for certain data in Signing Inference, which is a part of policy.
With Signing Inferences, PolicyManager can automatically infer the signing identies and use their default identity certificate to sign data packets.

.. code-block:: c++
   
   if(signingCertificateName.isEmpty())
   {
     Name signingIdentity = m_policyManager->inferSigningIdentity(data.getName());
     signByIdentity(data, signingIdentity);
   }

.. code-block:: c++

   if(signingIdentity.isEmpty())
   {
     signingIdentity = m_policyManager->inferSigningIdentity(data.getName());
     signByIdentity(data, signingIdentity);
   }

.. toctree::
   :maxdepth: 2



.. Indices and tables
.. ------------------

.. * :ref:`genindex`
.. * :ref:`modindex`
.. * :ref:`search`

