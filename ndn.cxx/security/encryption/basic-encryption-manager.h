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

#include "ndn.cxx/security/encryption/symmetric-key.h"
#include "ndn.cxx/security/identity/privatekey-storage.h"

namespace ndn
{

namespace security
{
  class BasicEncryptionManager : public EncryptionManager
  {
  public:
    BasicEncryptionManager(Ptr<PrivatekeyStorage> privateStorage, const string & encryptionPath);
    
    virtual ~BasicEncryptionManager() {}

    /*
     *
     */
    virtual void 
    createSymKey(const Name & keyName, KeyType keyType, const Name & signkeyName = Name(), bool sym = true);
    
    virtual Ptr<Blob>
    encrypt(const Name & keyName, const Blob & blob, bool sym = true, EncryptMode em = EM_DEFAULT);

    virtual Ptr<Blob>
    decrypt(const Name & keyName, const Blob & blob, bool sym = true, EncryptMode em = EM_DEFAULT);

  private:
    bool
    doesKeyNameExist(const string & keyName);

    // bool 
    // doesEntryExist(const string & keyName, const string & keySeq);

    Ptr<SymmetricKey>
    getSymmetricKey(const string & keyName);

  private:
    sqlite3 * m_db;
    Ptr<PrivatekeyStorage> m_privateStorage;
    Name m_defaultKeyName;
    bool m_defaultSym;
  };

}//security

}//ndn

#endif
