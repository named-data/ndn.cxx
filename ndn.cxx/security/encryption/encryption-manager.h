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
    createSymKey(const Name & keyName, KeyType keyType, const string & signkeyName = "", bool sym = true) = 0;

    virtual Ptr<Blob>
    encrypt(const Name & keyName, const Blob & blob, bool sym = false, EncryptMode em = EM_DEFAULT) = 0;

    virtual Ptr<Blob>
    decrypt(const Name & keyName, const Blob & blob, bool sym = false, EncryptMode em = EM_DEFAULT) = 0;
    
  protected:
    
  };

}//security

}//ndn

#endif
