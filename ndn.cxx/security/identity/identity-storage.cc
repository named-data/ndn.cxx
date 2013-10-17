/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "identity-storage.h"
#include "ndn.cxx/security/exception.h"

using namespace std;

namespace ndn
{

namespace security
{
  Name
  IdentityStorage::getNewKeyName (const Name & identity, bool ksk)
  {
    TimeInterval ti = time::NowUnixTimestamp();
    ostringstream oss;
    oss << ti.total_seconds();

    string keyIdStr;
    
    if (ksk)
      keyIdStr = ("KSK-" + oss.str());
    else
      keyIdStr = ("DSK-" + oss.str());


    Name keyName = Name(identity).append(keyIdStr);

    if(doesKeyExist(keyName))
      throw SecException("Key name has already existed");

    return keyName;
  }

  Name 
  IdentityStorage::getDefaultCertificateNameForIdentity (const Name & identity)
  {
    Name keyName = getDefaultKeyNameForIdentity(identity);
    
    return getDefaultCertificateNameForKey(keyName);
  }


}//security

}//ndn
