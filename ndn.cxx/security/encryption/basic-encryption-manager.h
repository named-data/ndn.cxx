/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_BASIC_ENCRYPTION_MANAGER_H
#define NDN_BASIC_ENCRYPTION_MANAGER_H

#include "encryption-manager.h"

#include <sqlite3.h>

#include "ndn.cxx/security/identity/privatekey-store.h"

namespace ndn
{

namespace security
{
  class BasicEncryptionManager : public EncryptionManager
  {
  public:
    BasicEncryptionManager(Ptr<PrivatekeyStore> privateStorage);
    
    virtual ~BasicEncryptionManager() {}

    /*
     *
     */
    virtual void 
    CreateKey(const Name & keyName, KeyType keyType);

    virtual void
    InstallKey(const Name & keyName, const Blob & blob);
    
    virtual Ptr<Blob>
    Encrypt(const Publickey & publicKey, const Blob & blob);

    virtual Ptr<Blob>
    Encrypt(const Name & keyName, const Blob & blob);

    virtual Ptr<Blob>
    Decrypt(const Name & keyName, const Blob & blob, bool sym = false);

  private:
    sqlite3 * m_db;
    Ptr<PrivatekeyStore> m_privateStorage;
  };

}//security

}//ndn

#endif
