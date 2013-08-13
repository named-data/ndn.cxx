/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "basic-encryption-manager.h"

namespace ndn
{

namespace security
{
  BasicEncryptionManager::BasicEncryptionManager(Ptr<PrivatekeyStore> privateStorage)
    :m_privateStorage(privateStorage)
  {
    //TODO:
  }
  void 
  BasicEncryptionManager::CreateKey(const Name & keyName, KeyType keyType)
  {
    //TODO:
  }

  void
  BasicEncryptionManager::InstallKey(const Name & keyName, const Blob & blob)
  {
  }
    
  Ptr<Blob>
  BasicEncryptionManager::Encrypt(const Publickey & publicKey, const Blob & blob)
  {
    return NULL;
  }

  Ptr<Blob>
  BasicEncryptionManager::Encrypt(const Name & keyName, const Blob & blob)
  {
    return NULL;
  }

  Ptr<Blob>
  BasicEncryptionManager::Decrypt(const Name & keyName, const Blob & blob, bool sym)
  {
    return NULL;
  }
  

}//security

}//ndn
