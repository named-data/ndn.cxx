/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_IDENTITY_STORAGE_H
#define NDN_IDENTITY_STORAGE_H

#include "ndn.cxx/security/security-common.h"
#include "ndn.cxx/security/certificate/certificate.h"

using namespace boost::posix_time;

namespace ndn
{

namespace security
{

  class IdentityStorage
  {
  public:
    IdentityStorage() {}

    virtual 
    ~IdentityStorage () {}


    virtual bool 
    doesIdentityExist (const Name & identity) = 0;

    virtual void
    addIdentity (const Name & identity) = 0;

    virtual bool 
    revokeIdentity () = 0;



    virtual Name 
    getNewKeyName (const Name & identity, bool ksk) = 0;

    virtual bool 
    doesKeyExist (const Name & keyName) = 0;

    virtual Name 
    getKeyNameForCert (const Name & certName) = 0;

    virtual void 
    addKey (const Name & keyName, KeyType keyType, Ptr<Blob> pubKeyBlob) = 0;

    virtual Ptr<Blob>
    getKey (const Name & keyName) = 0;

    virtual void 
    activateKey (const Name & keyName) = 0;

    virtual void 
    deactivateKey (const Name & keyName) = 0;


    virtual bool
    doesCertificateExist (const Name & certName) = 0;

    virtual void 
    addCertificate (const Certificate & certificate) = 0;

    virtual Ptr<Data> 
    getCertificate (const Name & certName, bool any = false) = 0;

    /*****************************************
     *           Get/Set Default             *
     *****************************************/

    virtual Name 
    getDefaultIdentity () = 0;

    virtual Name 
    getDefaultKeyName (const Name & identity) = 0;
    
    virtual Name 
    getDefaultCertNameForIdentity (const Name & identity) = 0;

    virtual Name 
    getDefaultCertNameForKey (const Name & keyName) = 0;

    virtual void 
    setDefaultIdentity (const Name & identity) = 0;

    virtual void 
    setDefaultKeyName (const Name & keyName) = 0;

    virtual void 
    setDefaultCertName (const Name & keyName, const Name & certName) = 0;
  };


}//security

}//ndn

#endif
