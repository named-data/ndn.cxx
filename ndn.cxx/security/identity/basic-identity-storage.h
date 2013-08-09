/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_BASIC_IDENTITY_STORAGE_H
#define NDN_BASIC_IDENTITY_STORAGE_H

#include <sqlite3.h>

#include "ndn.cxx/common.h"

#include "identity-storage.h"

namespace ndn
{

namespace security
{

  class BasicIdentityStorage : public IdentityStorage
  {
  public:
    BasicIdentityStorage();

    virtual ~BasicIdentityStorage() {}

    virtual bool 
    doesIdentityExist (const Name & identity);

    virtual void
    addIdentity (const Name & identity);

    virtual bool 
    revokeIdentity ();



    virtual Name 
    getNewKeyName (const Name & identity, bool ksk);

    virtual bool 
    doesKeyExist (const Name & keyName);

    virtual Name 
    getKeyNameForCertExist (const Name & certName);

    virtual void 
    addKey (const Name & keyName, KeyType keyType, Ptr<Blob> pubKeyBlob);

    virtual Ptr<Blob>
    getKey (const Name & keyName);

    virtual void 
    activateKey (const Name & keyName);

    virtual void 
    deactivateKey (const Name & keyName);



    virtual bool 
    doesCertificateExist (const Name & certName);

    virtual void 
    addCertificate (const Certificate & certificate);

    virtual Ptr<Data> 
    getCertificate (const Name & certName, bool any = false);

    virtual Name 
    getDefaultIdentity ();

    virtual Name 
    getDefaultKeyName (const Name & identity);
    
    virtual Name 
    getDefaultCertNameForIdentity (const Name & identity);

    virtual Name 
    getDefaultCertNameForKey (const Name & keyName);

    virtual void 
    setDefaultIdentity (const Name & identity);

    virtual void 
    setDefaultKeyName (const Name & keyName);

    virtual void 
    setDefaultCertName (const Name & keyName, const Name & certName);

  private:
    virtual void
    updateKeyStatus(const Name & keyName, bool active);

  private:
    sqlite3 *m_db;
    Time m_lastUpdated;
  };

}//security

}//ndn


#endif
