/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_ENCRYPTION_MANAGER_H
#define NDN_ENCRYPTION_MANAGER_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"

#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/security/certificate/publickey.h"

namespace ndn
{

namespace security
{
  class EncryptionManager
  {
  public:
    EncryptionManager() {}

    virtual ~EncryptionManager() {}
    
    virtual void 
    CreateKey(const Name & keyName, KeyType keyType) = 0;

    virtual void
    InstallKey(const Name & keyName, const Blob & blob) = 0;
    
    virtual Ptr<Blob>
    Encrypt(const Publickey & publicKey, const Blob & blob) = 0;

    virtual Ptr<Blob>
    Encrypt(const Name & keyName, const Blob & blob) = 0;

    virtual Ptr<Blob>
    Decrypt(const Name & keyName, const Blob & blob, bool sym = false) = 0;
    
  };

}//security

}//ndn

#endif
