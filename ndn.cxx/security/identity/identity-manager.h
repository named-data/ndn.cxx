/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_IDENTITY_MANAGER_H
#define NDN_IDENTITY_MANAGER_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/name.h"
#include "ndn.cxx/fields/signature.h"

#include "ndn.cxx/security/security-common.h"

#include "ndn.cxx/security/identity/identity-storage.h"
#include "ndn.cxx/security/identity/privatekey-store.h"

namespace ndn
{

namespace security
{

  class IdentityManager
  {
  public:
    IdentityManager(Ptr<IdentityStorage> publicStorage, Ptr<PrivatekeyStore> privateStorage);

    virtual 
    ~IdentityManager() {};

    virtual void
    createIdentity (const Name & identity);

    /* Defualt identity is the default idenity for the user, it should not be configured by application.
     * We should provide a separate tool to configure user default identity.
     * Application should maintain its own default identity.
     */
    // virtual void
    // setDefaultIdentity (const Name & identity);

    virtual Name
    getDefaultIdentity ();


    virtual Name
    generateRSAKeyPair (const Name & identity, bool ksk = false, int keySize = 2048);

    virtual void
    setDefaultKeyForIdentity (const Name & keyName);

    virtual Name
    generateRSAKeyPairAsDefault (const Name & identity, bool ksk = false, int keySize = 2048);


    virtual void
    addCertificate (const Certificate & certificate);

    virtual void
    setDefaultCertForKey (const Name & certName);

    virtual void
    addCertificateAsDefault (const Certificate & certificate);

    virtual Ptr<Data>
    getCertificate (const Name & certName);
    
    virtual Ptr<Data>
    getAnyCertificate (const Name & certName);


    virtual Name
    getDefaultCertNameByIdentity (const Name & identity);
    
    virtual Name
    getDefaultCertName ();
    
    virtual Ptr<Signature>
    signByIdentity (const Blob & blob, const Name & identity);

    virtual Ptr<Signature>
    signByCert (const Blob & blob, const Name & certName);

  private:
    virtual Name
    generateKeyPair (const Name & identity, bool ksk = false, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

    virtual Ptr<Data>
    selfSign (const Name & keyName);
    
  private:
    Ptr<IdentityStorage> m_publicStorage;
    Ptr<PrivatekeyStore> m_privateStorage;
  };

}//security

}//ndn


#endif
