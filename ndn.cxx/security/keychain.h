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

#include "identity/identity-manager.h"
#include "policy/policy-manager.h"
#include "encryption/encryption-manager.h"
#include "policy/policy-rule.h"
// #include "certificate/certificate.h"

#include "ndn.cxx/wrapper/closure.h"



using namespace std;

namespace ndn
{

  class Wrapper;

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
    /**
     * @brief Constructor
     * @param privateStorage the storage for private keys and some secret keys
     * @param policyPath the path to the policy file
     * @param encryptionPath the path to the encryption database
     */
    Keychain(Ptr<IdentityManager> identityManager, 
             Ptr<PolicyManager> policyManager, 
             Ptr<EncryptionManager> encryptionManager);

    /**
     * @brief Destructor
     */
    virtual
    ~Keychain(){};

    /*****************************************
     *          Identity Management          *
     *****************************************/

    /**
     * @brief Create identity, by default it will create a pair of Key-Signing-Key (KSK) for this identity and a self-signed certificate of the KSK
     * @param identity the name of the identity
     * @return the key name of the auto-generated KSK of the identity 
     */
    Name 
    createIdentity(const Name & identity);

    /**
     * @brief get the default identity name
     * @return the name of the default identity
     */
    Name
    getDefaultIdentity ();

    /**
     * @brief Generate a pair of RSA keys for the specified identity
     * @param identity the name of the identity
     * @param ksk create a KSK or not, true for KSK, false for DSK 
     * @param keySize the size of the key
     * @return the generated key name 
     */
    Name
    generateRSAKeyPair (const Name & identity, bool ksk = false, int keySize = 2048);

    /**
     * @brief Set a key as the default key of an identity
     * @param keyName the name of the key
     * @param identity the name of the identity, if not specified the identity name can be inferred from the keyName
     */
    void
    setDefaultKeyForIdentity (const Name & keyName, const Name & identity = Name());

    /**
     * @brief Generate a pair of RSA keys for the specified identity and set it as default key of the identity
     * @param identity the name of the identity
     * @param ksk create a KSK or not, true for KSK, false for DSK 
     * @param keySize the size of the key
     * @return the generated key name
     */
    Name
    generateRSAKeyPairAsDefault (const Name & identity, bool ksk = false, int keySize = 2048);

    /**
     * @brief Create a public key signing request
     * @param keyName the name of the key
     * @returns signing request blob
     */
    Ptr<Blob> 
    createSigningRequest(const Name & keyName);

    /**
     * @brief Install an identity certificate into identity
     * @param certificate the certificate in terms of Data packet
     */
    void 
    installIdentityCertificate(Ptr<IdentityCertificate> certificate);

    /**
     * @brief Set a certificate as the default certificate name of the corresponding key
     * @param certificateName the name of the certificate
     */
    void
    setDefaultCertificateForKey(const IdentityCertificate & certificate);

    /**
     * @brief Get certificate
     * @param certificateName name of the certificate
     * @returns certificate that is valid 
     */
    Ptr<Certificate> 
    getCertificate(const Name & certificateName);

    /**
     * @brief Get certificate even if it is not valid
     * @param certificateName name of the certificate
     * @returns certificate that is valid 
     */
    Ptr<Certificate>
    getAnyCertificate(const Name & certName);

    /**
     * @brief Get identity certificate
     * @param certificateName name of the certificate
     * @returns certificate that is valid 
     */
    Ptr<IdentityCertificate> 
    getIdentityCertificate(const Name & certificateName);

    /**
     * @brief Get identity certificate even if it is not valid
     * @param certificateName name of the certificate
     * @returns certificate that is valid 
     */
    Ptr<IdentityCertificate> 
    getAnyIdentityCertificate(const Name & certificateName);

    /**
     * @brief Revoke a key
     * @param keyName the name of the key that will be revoked
     */
    void 
    revokeKey(const Name & keyName);

    /**
     * @brief Revoke a certificate
     * @param certificateName the name of the certificate that will be revoked
     */
    void 
    revokeCertificate(const Name & certificateName);

    inline Ptr<IdentityManager>
    getIdentityManager()
    { return m_identityManager; }

    /*****************************************
     *           Policy Management           *
     *****************************************/

    Ptr<PolicyManager>
    getPolicyManager();

    // /**
    //  * @brief Set a signing policy rule
    //  * @param policy the signing policy rule
    //  */
    // virtual void 
    // setSigningPolicyRule(Ptr<PolicyRule> policy);

    // /**
    //  * @brief Set verification exemption rule
    //  * @param exemption the verification exemption rule
    //  */
    // virtual void
    // setVerificationExemption(Ptr<Regex> exemption);

    // /**
    //  * @brief Set verification policy rule
    //  * @param policy the verification policy rule
    //  */
    // virtual void 
    // setVerificationPolicyRule(Ptr<PolicyRule> policy);

    // /**
    //  * @brief Set signing inference
    //  * @param inference the siging inference
    //  */
    // virtual void 
    // setSigningInference(Ptr<Regex> inference);

    // /**
    //  * @brief Set trust anchor
    //  * @param certificate the trust anchor
    //  */
    // virtual void 
    // setTrustAnchor(const Certificate & certificate);

    /*****************************************
     *              Sign/Verify              *
     *****************************************/

    /**
     * @brief Sign data
     * @param data the data packet that will be signed, on return the Signature of data will be set
     * @param certificate the certificate whose name will be put into KeyLocator
     */
    void 
    sign(Data & data, const Name & certificateName);
    
    /**
     * @brief Sign blob 
     * @param buf the blob that needs to be signed
     * @param certificate the certificate whose name will be put into KeyLocator
     * @return the Signature
     */
    Ptr<Signature> 
    sign(const Blob & buf, const Name & certificateName);

    /**
     * @brief Sign data 
     * @param data the data packet that will be signed, on return the Signature of data will be set
     * @param identity the identity name
     */
    void 
    signByIdentity(Data & data, const Name & identity);

    /**
     * @brief Sign blob 
     * @param buf the blob that needs to be signed
     * @param identity the identity name
     * @return the Signature
     */
    Ptr<Signature> 
    signByIdentity (const Blob & blob, const Name & identity);

    /**
     * @brief Verify data packet
     * @param data the data packet that will be verified
     * @param verifiedCallback the callback function that will be called if the target data has been verified
     * @param failureCallback the callback function that will be called if the target data cannot be verified
     * @param stepCount a counter to track how many validation steps have been gone through
     */
    void 
    verifyData(Ptr<Data> data, 
               const DataCallback & verifiedCallback, 
               const UnverifiedCallback& unverifiedCallback,
               int stepCount = 0);

    /*****************************************
     *           Encrypt/Decrypt             *
     *****************************************/

    /**
     * @brief Generate a symmetric key
     * @param keyName the name of the generated key
     * @param keyType the type of the key, e.g. AES
     */
    void 
    generateSymmetricKey(const Name & keyName, KeyType keyType);

    /**
     * @brief Encrypt blob
     * @param keyName the name of the encrypting key
     * @param blob the blob that will be encrypted
     * @param sym if true symmetric encryption is used, otherwise asymmetric encryption is used
     * @param em the encryption mode
     * @return the encrypted blob
     */
    Ptr<Blob> 
    encrypt(const Name & keyName, const Blob & blob, bool sym = true, EncryptMode em = EM_DEFAULT);

    /**
     * @brief Decrypt blob
     * @param keyName the name of the decrypting key
     * @param blob the blob that will be decrypted
     * @param sym if true symmetric encryption is used, otherwise asymmetric encryption is used
     * @param em the encryption mode
     * @return the decrypted blob
     */
    Ptr<Blob> 
    decrypt(const Name & keyName, const Blob & blob, bool sym = true, EncryptMode em = EM_DEFAULT);
    
    /**
     * @brief Set the wrapper which will be used to fetch required certificates
     * @param wrapper the wrapper
     */
    void
    setWrapper(Wrapper * wrapper)
    {
      m_handler = wrapper;
    }

  private:  
    // /**
    //  * @brief Single intermediate step of verification
    //  * @param data the data packet that will be verified in this step
    //  * @param isFirst if the target data packet is the original data packet, otherwise the data packet is a intermediate certificate
    //  * @param stepCount the rest number of verification steps that can be executed
    //  * @param recursiveVerifiedCallback the callback function that will be called if the target data packet is valid
    //  * @param failureCallback the callback function that will be called if the target data cannot be verified
    //  */
    // virtual void 
    // stepVerify(Ptr<Data> data, 
    //            const bool isFirst,
    //            const int stepCount, 
    //            const RecursiveVerifiedCallback & recursiveVerifiedCallback, 
    //            const VerifyFailCallback & failureCallback);

    /**
     * @brief Callback function that will be called if the interest for certificate times out
     * @param closure the closure that stores callback functions
     * @param interest the Interest packet that times out
     * @param retry the number of rest retrials
     * @param failureCallback the callback function that will be called if the retransmission eventaully fails
     */
    void
    onCertificateInterestTimeout(Ptr<Closure> closure, 
                                 Ptr<Interest> interest, 
                                 int retry, 
                                 const UnverifiedCallback& unverifiedCallback,
                                 Ptr<Data> data);

    // /**
    //  * @brief Callback function that will be called if the certificate has been validated
    //  * @param certificate the certificate that has been validated
    //  * @param data the data packet that needs to be verified by the certificate
    //  * @param preRecurVerifyCallback the callback function that will be called if the data packet can be validated
    //  * @param failureCallback the callback function that will be called if the data packet cannot be validated
    //  */
    // virtual void
    // onCertificateVerified(Ptr<Data>certificate, 
    //                       Ptr<Data>data, 
    //                       const RecursiveVerifiedCallback &preRecurVerifyCallback, 
    //                       const VerifyFailCallback &failureCallback);

    // virtual void
    // onOriginalCertVerified(Ptr<Certificate> cert, 
    //                        Ptr<Data>data, 
    //                        const VerifiedCallback &verifiedCallback, 
    //                        const VerifyFailCallback &failureCallback);

  private:
    Ptr<IdentityManager> m_identityManager;
    Ptr<PolicyManager> m_policyManager;
    Ptr<EncryptionManager> m_encryptionManager;
    const int m_maxStep;
    Wrapper* m_handler;
  };
  

}//security

}//ndn

#endif
