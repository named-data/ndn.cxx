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
    
    /**
     * @brief Constructor
     */
    Publickey () {}

    /**
     * @brief Constructor
     * @param algorithm algorithm of public key
     * @param keyBlob the blob of PublicKeyInfo in terms of DER
     */
    Publickey (const OID & algorithm, const Blob & keyBlob);

    /*
     * @brief copy Constructor of Publickey
     * @param publickey
     */    
    Publickey (const Publickey & publickey);

    /**
     * @brief encode the public key into DER
     * @return the encoded DER syntax tree
     */
    Ptr<der::DerNode>
    toDER();

    /**
     * @brief decode the public key from DER blob
     * @param blob the DER blob
     * @return the decoded public key
     */
    static Ptr<Publickey>
    fromDER(Ptr<Blob> blob);

    /**
     * @brief decode the public key from DER blob
     * @param blob the DER blob
     * @return the decoded public key
     */
    static Ptr<Publickey>
    fromDER(const Blob& blob);

    /*
     * @brief get the digest of the public key
     * @param digestAlgo the digest algorithm, ndn::security::DIGEST_SHA256 by default 
     */
    Ptr<const Blob> 
    getDigest (DigestAlgorithm digestAlgo = DIGEST_SHA256) const;

    /*
     * @brief get the raw bytes of the public key in DER format
     */
    Blob & 
    getKeyBlob ()
    {
      return m_key; 
    }

    /*
     * @brief get the raw bytes of the public key in DER format
     */ 
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
