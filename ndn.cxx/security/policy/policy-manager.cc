/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "policy-manager.h"

#include "ndn.cxx/data.h"
#include "ndn.cxx/fields/signature-sha256-with-rsa.h"
#include "ndn.cxx/security/certificate/publickey.h"

#include <cryptopp/rsa.h>

#include "logging.h"

INIT_LOGGER("ndn.security.PolicyManager");

namespace ndn
{

namespace security
{

  bool 
  PolicyManager::verifySignature(const Blob & unsignedData, const Blob& sigBits, const Publickey & publickey)
  {
    using namespace CryptoPP;

    bool result = false;
    
    DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType)
      {
        RSA::PublicKey pubKey;
        ByteQueue queue;

        queue.Put((const byte*)publickey.getKeyBlob ().buf (), publickey.getKeyBlob ().size ());
        pubKey.Load(queue);

        if(DIGEST_SHA256 == digestAlg)
          {
            RSASS<PKCS1v15, SHA256>::Verifier verifier (pubKey);
            result = verifier.VerifyMessage((const byte*) unsignedData.buf(), unsignedData.size(), (const byte*)sigBits.buf(), sigBits.size());            
            _LOG_DEBUG("Signature verified? " << boolalpha << result);            
          }
      }
   
    return result;
  }

  bool 
  PolicyManager::verifySignature(const Data & data, const Publickey & publickey)
  {
    using namespace CryptoPP;

    Blob unsignedData(data.getSignedBlob()->signed_buf(), data.getSignedBlob()->signed_size());
    bool result = false;
    
    DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType)
      {
        RSA::PublicKey pubKey;
        ByteQueue queue;

        queue.Put((const byte*)publickey.getKeyBlob ().buf (), publickey.getKeyBlob ().size ());
        pubKey.Load(queue);

        if(DIGEST_SHA256 == digestAlg)
          {
            Ptr<const signature::Sha256WithRsa> sigPtr = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
            const Blob & sigBits = sigPtr->getSignatureBits();

            RSASS<PKCS1v15, SHA256>::Verifier verifier (pubKey);
            result = verifier.VerifyMessage((const byte*) unsignedData.buf(), unsignedData.size(), (const byte*)sigBits.buf(), sigBits.size());            
            _LOG_DEBUG("Signature verified? " << data.getName() << " " << boolalpha << result);
            
          }
      }
   
    return result;
  }


}//security

}//ndn
