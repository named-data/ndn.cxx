/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_PUBLICKEY_H
#define NDN_PUBLICKEY_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/helpers/oid.h"

namespace ndn
{

namespace security
{
  class Publickey
  {
  public:

    Publickey () {}
    /*
     * @brief Constructor of Publickey
     * @param blob bytes of public key in the format specided
     * @pem   true if PEM encoded, otherwise DER
     */
    Publickey (const Blob & blob, bool pem =false);

    /*
     * @brief copy Constructor of Publickey
     * @param publickey 
     */    
    Publickey (const Publickey & publickey);

    /*
     * @brief get the digest of the public key
     * @param digestAlgo the digest algorithm, ndn::security::DIGEST_SHA256 by default 
     */
    Ptr<const Blob> 
    getDigest (DigestAlgorithm digestAlgo = DIGEST_SHA256) const;

    // Blob & 
    // getKeyBlob()
    // { 
    //   return m_key; 
    // }

    /*
     * @brief get the raw bytes
     */
    Blob & 
    getKeyBlob ()
    {
      return m_key; 
    }
    
    const Blob & 
    getKeyBlob () const
    {
      return m_key; 
    }
    
  private:
    void 
    fromDER (const Blob & blob);
    
    void 
    fromPEM (const Blob & blob);
    
  private:
    OID m_algorithm; //Algorithm
    Blob m_key;      //PublicKeyInfo in terms of DER
  };

}//security

}//ndn

#endif
