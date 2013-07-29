/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_IDENTITY_DB_H
#define NDN_IDENTITY_DB_H

#include <boost/date_time/posix_time/posix_time.hpp>

using namespace boost::posix_time;

namespace ndn
{

namespace security
{

  class IdentityDB
  {
  public:
    IdentityDB() {}

    virtual bool IdentityExist(const string & identity) = 0;

    virtual bool RevokeIdentity() = 0;

    virtual bool AddCertificate() = 0;

    virtual string GetNewKeyID(const string & identity) = 0;

    virtual bool AddKey(const string & identity, const string & keyID, const string & keyName, Ptr<Blob> digest, ptime ts) = 0;

    virtual bool ActivateKey(const string & identity, const string & keyID) = 0;

    virtual bool DeactivateKey(const string & identity, const string & keyID) = 0;

    virtual bool AddCertificate(const Blob & keyHash, const Name & cert_name, const int & cert_seq,
                                const string & cert_type, const Name & cert_signer, 
                                const ptime & notBefore, const ptime & notAfter,
                                const Blob & cert_data, const ptime & expire) = 0;

    virtual Ptr<Blob> GetCertificate(const Name & certName, const Name & certSigner, const string & certType) = 0;
  };


}//security

}//ndn

#endif
