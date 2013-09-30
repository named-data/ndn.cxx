/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_IDENTITY_MANAGER_H
#define NDN_IDENTITY_MANAGER_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/fields/signature.h"

#include "ndn.cxx/security/security-common.h"

#include "ndn.cxx/security/identity/identity-storage.h"
#include "ndn.cxx/security/identity/privatekey-storage.h"

namespace ndn
{

namespace security
{
  /**
   * @brief IdentityManager class, it is the interface of operation related to identity, keys, and certificate
   */
  class IdentityManager
  {
  public:
    /**
     * @brief Constructor 
     * @param publicStorage storage for identities, public keys, and certificates
     * @param privateStorage storage for private keys and some system symmetric keys
     */
    IdentityManager(Ptr<IdentityStorage> publicStorage, Ptr<PrivatekeyStorage> privateStorage);

    /**
     * @brief Destructor
     */
    virtual 
    ~IdentityManager() {};

    /**
     * @brief Create identity, by default it will create a pair of Key-Signing-Key (KSK) for this identity and a self-signed certificate of the KSK
     * @param identity the name of the identity
     * @return the key name of the auto-generated KSK of the identity 
     */
    virtual Name
    createIdentity (const Name & identity);

    /**
     * @brief Get default identity
     * @return the default identity name
     */
    virtual Name
    getDefaultIdentity ();

    /**
     * @brief Generate a pair of RSA keys for the specified identity
     * @param identity the name of the identity
     * @param ksk create a KSK or not, true for KSK, false for DSK 
     * @param keySize the size of the key
     * @return the generated key name 
     */
    virtual Name
    generateRSAKeyPair (const Name & identity, bool ksk = false, int keySize = 2048);

    /**
     * @brief Set a key as the default key of an identity
     * @param keyName the name of the key
     * @param identity the name of the identity, if not specified the identity name can be inferred from the keyName
     */
    virtual void
    setDefaultKeyForIdentity (const Name & keyName, const Name & identity = Name());

    /**
     * @brief Generate a pair of RSA keys for the specified identity and set it as default key of the identity
     * @param identity the name of the identity
     * @param ksk create a KSK or not, true for KSK, false for DSK 
     * @param keySize the size of the key
     * @return the generated key name
     */
    virtual Name
    generateRSAKeyPairAsDefault (const Name & identity, bool ksk = false, int keySize = 2048);

    /**
     * @brief Get public key with the specified name
     * @param keyName name of the key
     * @return the public key
     */
    virtual Ptr<Publickey>
    getPublickey(const Name & keyName);

    /**
     * @brief Create an identity certificate for a public key managed by this IdentityManager
     * @param keyName the name of public key to be signed
     * @param signerCertificateName the name of signing certificate
     * @param notBefore the notBefore value in the validity field of the generated certificate
     * @param notAfter the notAfter vallue in validity field of the generated certificate
     * @return the name of generated identity certificate
     */
    virtual Name
    createIdentityCertificate (const Name& keyName,
                               const Name& signerCertificateName,
                               const Time& notBefore,
                               const Time& notAfter);

    /**
     * @brief Create an idenity certificate for a public key supplied by caller
     * @param keyName the name of public key to be signed
     * @param publickey the public key to be signed
     * @param signerCertificateName the name of signing certificate
     * @param notBefore the notBefore value in the validity field of the generated certificate
     * @param notAfter the notAfter vallue in validity field of the generated certificate
     * @return the generated identity certificate
     */
    virtual Ptr<Certificate>
    createIdentityCertificate (const Name& keyName,
                               const Publickey& publickey,
                               const Name& signerCertificateName,
                               const Time& notBefore,
                               const Time& notAfter); 

    /**
     * @brief Add a certificate into the public storage
     * @param certificate the certificate to to added
     */
    virtual void
    addCertificate (Ptr<Certificate> certificate);

    /**
     * @brief Set the certificate as the default of its corresponding key
     * @param certificateName name of the certificate
     */
    virtual void
    setDefaultCertificateForKey (const Name & certificateName);

    /**
     * @brief Add a certificate into the public storage and set the certificate as the default of its corresponding identity
     * @param certificate the certificate to be added
     */
    virtual void
    addCertificateAsIdentityDefault (const Certificate & certificate);

    /**
     * @brief Add a certificate into the public storage and set the certificate as the default of its corresponding key
     * @brief certificate the certificate to be added
     */
    virtual void
    addCertificateAsDefault (const Certificate & certificate);

    /**
     * @brief Get a certificate with the specified name
     * @param certificateName name of the requested certificate
     * @return the requested certificate
     */
    virtual Ptr<Certificate>
    getCertificate (const Name & certificateName);
    
    /**
     * @brief Get a certificate even if the certificate is not valid anymore
     * @param certificateName name of the requested certificate
     * @return the requested certificate
     */
    virtual Ptr<Certificate>
    getAnyCertificate (const Name & certificateName);

    /**
     * @brief Get the default certificate name of the specified identity, which will be used when signing is performed based on identity
     * @param identity the name of the specified identity
     * @return the requested certificate name
     */
    virtual Name
    getDefaultCertificateNameByIdentity (const Name & identity);
    
    /**
     * @brief Get default certificate name of the default identity, which will be used when signing is based on identity and identity is not specified
     * @return the requested certificate name
     */
    virtual Name
    getDefaultCertificateName ();
    
    // /**
    //  * @brief Sign blob based on identity
    //  * @param blob the blob to be signed
    //  * @param identity the signing identity name
    //  * @return the generated signature
    //  */
    // virtual Ptr<Signature>
    // signByIdentity (const Blob & blob, const Name & identity);

    // /**
    //  * @brief Sign data based on identity
    //  * @param data the data packet to be signed, on return the Signature inside the data packet will be set
    //  * @param identity the signing identity name
    //  */
    // virtual void
    // signByIdentity (Data & data, const Name & identity);

    /**
     * @brief sign blob based on certificate name
     * @param blob the blob to be signed
     * @param certificateName the signing certificate name
     * @return the generated signature
     */
    virtual Ptr<Signature>
    signByCertificate (const Blob & blob, const Name & certificateName);
    
    /**
     * @brief sign data packet based on certificate name
     * @param data the data packet to be signed, on return the Signature inside the data packet will be set
     * @param certificateName the signing certificate name
     */
    virtual void
    signByCertificate (Data & data, const Name & certificateName);

    // void
    // loadDefaultIdentity();

  private:

    // virtual void
    // setDefaultIdentity (const Name & identity);

    /**
     * @brief Generate a key pair for the specified identity
     * @param identity the name of the specified identity
     * @param ksk if true the generated key is a KSK, otherwise DSK
     * @param keyType the type of the key pair, e.g. RSA
     * @param keySize the size of the key pair
     * @return name of the generated key
     */
    virtual Name
    generateKeyPair (const Name & identity, bool ksk = false, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     * @brief Generate a self-signed certificate for a public key
     * @param keyName name of the public key
     * @return the generated certificate
     */
    virtual Ptr<Data>
    selfSign (const Name & keyName);
    
  private:
    Ptr<IdentityStorage> m_publicStorage;
    Ptr<PrivatekeyStorage> m_privateStorage;
  };

}//security

}//ndn


#endif
