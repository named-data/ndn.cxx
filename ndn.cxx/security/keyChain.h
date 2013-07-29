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
#include "ndn.cxx/security/privateKeyStore.h"
#include "ndn.cxx/security/identity-db.h"
#include "ndn.cxx/security/policyManager.h"
#include "ndn.cxx/security/certificate/certificate-data.h"

using namespace std;

namespace ndn
{

namespace security
{
  class KeyChain{
  public:
    KeyChain();

    /*****************************************
     *          Identity Management          *
     *****************************************/

    /**
     * @brief Create identity, by default it will create a pair of key for this identity
     * @param identity the name of the identity
     * @returns True if succeeds, False otherwise
     */
    virtual bool CreateIdentity(const string & identity);

    /**
     * @brief Generate a pair of asymmetric keys
     * @param identity the name of the identity
     * @param keyID on return the identifier of the key 
     * @param keyType the type of the key
     * @param keySize the size of the key
     * @returns True if succeeds, False otherwise
     */
    virtual bool GenerateKeyPair(const string & identity, string & keyID, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     * @brief Create a public key signing request
     * @param identity the name of the identity
     * @param keyID the identifier of the public key
     * @param keyFormat the format of the request
     * @param pem True if output is encoded as PEM, False if output is encoded as DER
     * @returns signing request blob
     */
    virtual Ptr<Blob> CreateSigningRequest(const string & identity, const string & keyID, KeyFormat keyFormat=KEY_PUBLIC_OPENSSL, bool pem=false);

    /**
     * @brief Install a certificate into identity
     * @param identity the name of the identity
     * @param keyID the identifier of the public key
     * @param certificate the certificate in terms of Data packet
     * @returns True if succeeds, False otherwise
     */
    virtual bool InstallCertificate(const string & identity, const string & keyID, const Data & certificate);


    /**
     * @brief Get certificate for publishing
     * @param certName name of the cert
     * @param certSigner signer of the cert
     * @param certType type of the cert
     * @returns certificate Data 
     */
    virtual Ptr<Blob> GetCertificate(const Name & certName, const Name & certSigner, const string & certType);

    virtual Ptr<Blob> RevokeKey(const Name & identity, string keyID);

    virtual Ptr<Blob> RevokeCertificate(const Name & certName, const int & certSeq);

    /*****************************************
     *           Policy Management           *
     *****************************************/

    virtual bool SetSigningPolicy(const string & policy);

    virtual bool SetVerificationPolicy(const string & policy);


    /*****************************************
     *              Sign/Verify              *
     *****************************************/

    virtual Ptr<Blob> Sign();

    virtual bool Verify(const Data & data);

    /*****************************************
     *           Encrypt/Decrypt             *
     *****************************************/

    virtual Ptr<Blob> GenerateSymmetricKey();

    virtual Ptr<Blob> Encrypt();

    virtual Ptr<Blob> Decrypt();

  private:
    Ptr<Blob> Digest(Ptr<Blob>blob);

  private:
    Ptr<IdentityDB> m_identityDB;
    Ptr<PrivateKeyStore> m_privateKeyStore;
    Ptr<PolicyManager> m_policyManager;
  };
  

}//security

}//ndn

#endif
