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
#include <map>

#include "ndn.cxx/common.h"
#include "ndn.cxx/data.h"
#include "ndn.cxx/interest.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/fields/blob.h"
#include "ndn.cxx/fields/signature.h"
#include "ndn.cxx/regex/regex.h"

#include "cert-cache.h"

#include "identity/identity-manager.h"
#include "policy/policy-manager.h"
#include "encryption/encryption-manager.h"
#include "policy/policy-rule.h"
#include "certificate/certificate.h"

#include "ndn.cxx/wrapper/closure.h"



using namespace std;

namespace ndn
{

  class FakeWrapper;

namespace security
{

  typedef boost::function<void (Ptr<Data>)> VerifiedCallback;
  typedef boost::function<void ()> VerifyFailCallback;
  typedef boost::function<void (Ptr<Data>)> RecursiveVerifiedCallback;

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
    Keychain(Ptr<PrivatekeyStore> privateStorage, const string & policyPath, const string & encryptionPath);

    virtual
    ~Keychain(){};

    /*****************************************
     *          Identity Management          *
     *****************************************/

    /**
     * @brief Create identity, by default it will create a pair of key for this identity
     * @param identity the name of the identity
     */
    virtual Name 
    createIdentity(const Name & identity);

    virtual Name
    getDefaultIdentity ();

    /**
     * @brief Generate a pair of RSA keys
     * @param identity the name of the identity
     * @param keyName on return the identifier of the key 
     * @param keySize the size of the key
     * @returns pointer to the keyName, NULL if key generation fails
     */
    virtual Name
    generateRSAKeyPair (const Name & identity, bool ksk = false, int keySize = 2048);

    virtual void
    setDefaultKeyForIdentity (const Name & keyName);

    virtual Name
    generateRSAKeyPairAsDefault (const Name & identity, bool ksk = false, int keySize = 2048);

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
     */
    virtual void 
    installCertificate(Ptr<Certificate> certificatePtr);


    /**
     * @brief Get certificate for publishing
     * @param certName name of the cert
     * @param certSigner signer of the cert
     * @param certType type of the cert
     * @returns certificate Data 
     */
    virtual Ptr<Certificate> 
    getCertificate(const Name & certName);

    virtual Ptr<Certificate>
    getAnyCertificate(const Name & certName);

    virtual Ptr<Blob> 
    revokeKey(const Name & keyName);

    virtual Ptr<Blob> 
    revokeCertificate(const Name & certName);

    /*****************************************
     *           Policy Management           *
     *****************************************/

    virtual void 
    setSigningPolicyRule(Ptr<PolicyRule> policy);

    virtual void
    setVerificationExemption(Ptr<Regex> exempt);

    virtual void 
    setVerificationPolicyRule(Ptr<PolicyRule> policy);

    virtual void 
    setSigningInference(Ptr<Regex> inference);

    virtual void 
    setTrustAnchor(const Certificate & certificate);

    /*****************************************
     *              Sign/Verify              *
     *****************************************/

    virtual void 
    sign(Data & data, const Name & signerName = Name(), bool byID = true);
    
    virtual Ptr<Signature> 
    sign(const Blob & buf, const Name & signerName, bool byID = true);

    virtual void 
    verifyData(Ptr<Data> dataPtr, const VerifiedCallback & verifiedCallback, const VerifyFailCallback & failureCallback);

    /*****************************************
     *           Encrypt/Decrypt             *
     *****************************************/

    virtual void 
    generateSymmetricKey(const Name & keyName, KeyType keyType);

    virtual Ptr<Blob> 
    encrypt(const Name & keyName, const Blob & blob, bool sym = true, EncryptMode em = EM_DEFAULT);

    virtual Ptr<Blob> 
    decrypt(const Name & keyName, const Blob & blob, bool sym = true, EncryptMode em = EM_DEFAULT);
    

    //TMP:
    Ptr<Data>
    fakeFecthData(const Name & name);

    void
    setFakeWrapper(FakeWrapper * wrapper)
    {
      m_handler = wrapper;
    }

  private:    
    Ptr<Data> 
    fetchData(const Name & name);

    virtual void 
    stepVerify(Ptr<Data> dataPtr, 
               const int stepCount, 
               const RecursiveVerifiedCallback & recursiveVerifiedCallback, 
               const VerifyFailCallback & failureCallback);

    virtual void
    onCertInterestTimeout(Ptr<Closure> closurePtr, Ptr<Interest> interestPtr, int retry, const VerifyFailCallback & failureCallback);

    virtual void
    onCertVerified(Ptr<Data>cert, 
                   Ptr<Data>data, 
                   const RecursiveVerifiedCallback &preRecurVerifyCallback, 
                   const VerifyFailCallback &failureCallback);

    // virtual void
    // onOriginalCertVerified(Ptr<Certificate> cert, 
    //                        Ptr<Data>data, 
    //                        const VerifiedCallback &verifiedCallback, 
    //                        const VerifyFailCallback &failureCallback);

  private:
    Ptr<IdentityManager> m_identityManager;
    Ptr<PolicyManager> m_policyManager;
    Ptr<EncryptionManager> m_encryptionManager;
    map<Name, Certificate> m_certCache;
    const int m_maxStep;
    FakeWrapper* m_handler;
  };
  

}//security

}//ndn

#endif
