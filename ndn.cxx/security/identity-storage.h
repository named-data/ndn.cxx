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

#include <boost/date_time/posix_time/posix_time.hpp>

#include "certificate/certificate.h"

using namespace boost::posix_time;

namespace ndn
{

namespace security
{

  class IdentityStorage
  {
  public:
    IdentityStorage() {}

    virtual bool doesIdentityExist(const Name & identity) = 0;

    virtual bool revokeIdentity() = 0;

    virtual bool addCertificate() = 0;

    virtual Name getNewKeyName(const Name & identity) = 0;

    virtual bool doesKeyExist(const Name & keyName) = 0;

    virtual bool addKey(const Name & identity, const Name & keyName, Ptr<Blob> digest, Time ts) = 0;

    virtual bool activateKey(const string & identity, const string & keyID) = 0;

    virtual bool deactivateKey(const string & identity, const string & keyID) = 0;

    virtual bool addCertificate(const Certificate & certificate) = 0;

    virtual Ptr<Certificate> getCertificate(const Name & certName, const Name & certSigner, const string & certType) = 0;

    virtual string getKeyNameForCert(const Name & certName, const int & certSeq = -1) = 0;
    

    /*****************************************
     *           Get/Set Default             *
     *****************************************/

    virtual Name getDefaultIdentity() = 0;

    virtual Name getDefaultKeyName(const Name & identity) = 0;
    
    virtual Name getDefaultCertNameForIdentity(const Name & identity) = 0;

    virtual Name getDefaultCertNameForKey(const Name & keyName) = 0;

    virtual void setDefaultIdentity(const Name & identity) = 0;

    virtual void setDefaultKeyName(const Name & identity, const Name & keyName) = 0;

    virtual void setDefaultCertName(const Name & keyName, const Name & certName) = 0;
  };


}//security

}//ndn

#endif
