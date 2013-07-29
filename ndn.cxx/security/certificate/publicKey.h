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
#include "oid.h"

namespace ndn
{

namespace security
{
  class PublicKey
  {
  public:
    PublicKey(const Blob & blob, bool pem);

    Ptr<Blob> GetDigest();
    
  private:
    bool FromDER(const Blob & blob);
    
    bool FromPEM(const Blob & blob);
    
  private:
    Ptr<OID> m_algorithm; //Algorithm
    Ptr<Blob> m_keyBits;  //Public Key Bits
    Ptr<Blob> m_key;  //PublicKeyInfo in terms of DER
  };

}//security

}//ndn

#endif
