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
#include "ndn.cxx/helpers/der/der.h"

namespace ndn
{

namespace security
{
  class Publickey
  {
  public:

    Publickey () {}

    Publickey (const OID & algorithm, const Blob & keyBlob);

    /*
     * @brief copy Constructor of Publickey
     * @param publickey 
     */    
    Publickey (const Publickey & publickey);

    Ptr<der::DerNode>
    toDER();

    static Ptr<Publickey>
    fromDER(Ptr<Blob> blob);

    static Ptr<Publickey>
    fromDER(const Blob& blob);

    /*
     * @brief get the digest of the public key
     * @param digestAlgo the digest algorithm, ndn::security::DIGEST_SHA256 by default 
     */
    Ptr<const Blob> 
    getDigest (DigestAlgorithm digestAlgo = DIGEST_SHA256) const;

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
    OID m_algorithm; //Algorithm
    Blob m_key;      //PublicKeyInfo in terms of DER
  };

}//security

}//ndn

#endif
