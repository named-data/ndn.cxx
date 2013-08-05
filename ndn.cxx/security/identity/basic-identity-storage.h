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

    virtual bool 
    revokeIdentity ();

    virtual bool 
    addCertificate ();

    virtual Name 
    getNewKeyName (const Name & identity);

    virtual bool 
    doesKeyExist (const Name & keyName);

    virtual bool 
    addKey (const Name & identity, const Name & keyName, Ptr<Blob> digest, Time ts);

    virtual bool 
    activateKey (const string & identity, const string & keyID);

    virtual bool 
    deactivateKey (const string & identity, const string & keyID);

    virtual bool 
    addCertificate (const Certificate & certificate);

    virtual Ptr<Certificate> 
    getCertificate (const Name & certName);

    virtual string 
    getKeyNameForCert (const Name & certName, const int & certSeq = -1);

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
    setDefaultKeyName (const Name & identity, const Name & keyName);

    virtual void 
    setDefaultCertName (const Name & keyName, const Name & certName);

  private:
    sqlite3 *m_db;
    Time m_lastUpdated;
  };

}//security

}//ndn


#endif
