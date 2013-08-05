/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_KEYCHAIN_H
#define NDN_KEYCHAIN_H

#include <string>

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/fields/signature.h"

#include "privatekey-store.h"
#include "cert-cache.h"

#include "identity/identity-storage.h"
#include "policy/policy-manager.h"
#include "policy/policy.h"
#include "certificate/certificate.h"



using namespace std;

namespace ndn
{

namespace security
{
  /**
   * @brief Keychain class, the main class of security library
   *
   * Keychain provide a set of interfaces to the security libray,
   * such as identity management, policy configuration, security
   * transform (packet signing and verification, encryption and 
   * decryption), and etc.
   */
  class Keychain{
  public:    
    Keychain(int maxStep = 100);

    /*****************************************
     *          Identity Management          *
     *****************************************/

    /**
     * @brief Create identity, by default it will create a pair of key for this identity
     * @param identity the name of the identity
     * @returns True if succeeds, False otherwise
     */
    virtual bool 
    createIdentity(const Name & identity);

    /**
     * @brief Generate a pair of asymmetric keys
     * @param identity the name of the identity
     * @param keyName on return the identifier of the key 
     * @param keyType the type of the key
     * @param keySize the size of the key
     * @returns pointer to the keyName, NULL if key generation fails
     */
    virtual Name 
    generateKeyPair(const Name & identity, const Name & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     * @brief Helper function to generate a pair of RSA keys
     * @param identity the name of the identity
     * @param keyName on return the identifier of the key 
     * @param keySize the size of the key
     * @returns pointer to the keyName, NULL if key generation fails
     */
    virtual Name 
    generateRSAKeyPair(const Name & identity, const Name & keyName, int keySize = 2048)
    {
      return generateKeyPair(identity, keyName, KEY_TYPE_RSA, keySize); 
    }

    /**
     * @brief Helper function to generate a pair of DSA keys
     * @param identity the name of the identity
     * @param keyName on return the identifier of the key 
     * @param keySize the size of the key
     * @returns pointer to the keyName, NULL if key generation fails
     */
    virtual Name 
    generateDSAKeyPair(const Name & identity, const Name & keyName, int keySize = 2048)
    {
      return generateKeyPair(identity, keyName, KEY_TYPE_DSA, keySize); 
    }



    /**
     * @brief Create a public key signing request
     * @param identity the name of the identity
     * @param keyID the identifier of the public key
     * @param keyFormat the format of the request
     * @param pem True if output is encoded as PEM, False if output is encoded as DER
     * @returns signing request blob
     */
    virtual Ptr<Blob> 
    createSigningRequest(const Name & keyName);

    /**
     * @brief Install a certificate into identity
     * @param certificate the certificate in terms of Data packet
     * @returns True if succeeds, False otherwise
     */
    virtual bool 
    installCertificate(const Certificate & certificate);


    /**
     * @brief Get certificate for publishing
     * @param certName name of the cert
     * @param certSigner signer of the cert
     * @param certType type of the cert
     * @returns certificate Data 
     */
    virtual Ptr<Certificate> 
    getCertificate(const Name & certName);

    virtual Ptr<Blob> 
    revokeKey(const Name & keyName);

    virtual Ptr<Blob> 
    revokeCertificate(const Name & certName);

    /*****************************************
     *           Policy Management           *
     *****************************************/

    virtual void 
    setSigningPolicy(const string & policy);

    virtual void 
    setVerificationPolicy(const string & policy);

    virtual void 
    setSigningInference(const string & inference);

    virtual void 
    setTrustAnchor(const Certificate & certificate);

    /*****************************************
     *              Sign/Verify              *
     *****************************************/

    virtual void 
    sign(Data & data, const Name & certName = Name());
    
    virtual Ptr<Signature> 
    sign(const Blob & buf, const Name & certName);

    virtual bool 
    verify(const Data & data);

    virtual bool 
    verifySignature(const Data & data, const Publickey & publicKey);

    /*****************************************
     *           Encrypt/Decrypt             *
     *****************************************/

    virtual Ptr<Blob> 
    generateSymmetricKey();

    virtual Ptr<Blob> 
    encrypt();

    virtual Ptr<Blob> 
    decrypt();
    

  private:
    void
    sign(Data & data, const Name & keyName, const Publickey & publickey);
    
    Ptr<Data> 
    fetchData(const Name & name);

    virtual bool 
    stepVerify(const Data & data, const int & stepCount);

  private:
    Ptr<IdentityStorage> m_identityStorage;
    Ptr<PrivatekeyStore> m_privatekeyStore;
    Ptr<PolicyManager> m_policyManager;
    Ptr<CertificateCache> m_certCache;
    const int m_maxStep;
  };
  

}//security

}//ndn

#endif
