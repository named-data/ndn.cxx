/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef SIMPLEKEY_STORE_H
#define SIMPLEKEY_STORE_H

#include "ndn.cxx/common.h"

#include "privatekey-store.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <CoreServices/CoreServices.h>

namespace ndn
{

namespace security
{
  class SimpleKeyStore : public PrivatekeyStore
  {
  public:

  
	  SimpleKeyStore() {};

    /**
     * @brief destructor of PrivateKeyStore
     */    
    virtual 
    ~SimpleKeyStore() {};
    
		virtual bool 
    generateKeyPair(const string & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    /**
     *
     */
    virtual Ptr<Publickey> 
    getPublickey(const string & keyName);

    /**
     * @brief sign data
     * @param keyName the name of the signing key
     * @param digestAlgo the digest algorithm
     * @param pData the pointer to data
     * @returns signature, NULL if signing fails
     */
    virtual Ptr<Blob> 
    sign(const Blob & pData, const string & keyName, DigestAlgorithm digestAlgo = DIGEST_SHA256);
    
    /**
     * @brief decrypt data
     * @param keyName the name of the decrypting key
     * @param pData the pointer to encrypted data
     * @returns decrypted data
     */
    virtual Ptr<Blob> 
    decrypt(const string & keyName, const Blob & pData, bool sym = false);

    virtual Ptr<Blob> 
    encrypt(const string & keyName, const Blob & pData, bool sym = false);


    //TODO Symmetrical key stuff.
    /**
     * @brief generate a symmetric keys
     * @param keyName the name of the key 
     * @param keyType the type of the key, e.g. AES
     * @param keySize the size of the key
     * @returns true if key have been successfully generated
     */
    virtual void 
    generateKey(const string & keyName, KeyType keyType = KEY_TYPE_AES, int keySize = 256);

    virtual bool
    doesKeyExist(const string & keyName, KeyClass keyClass);

    
 	  private:
  };
  
}//security

}//ndn
#endif
