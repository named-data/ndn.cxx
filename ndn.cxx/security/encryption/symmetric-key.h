/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_SYMMETRIC_KEY_H
#define NDN_SYMMETRIC_KEY_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/fields/blob.h"

#include "ndn.cxx/security/security-common.h"

#include <string>

using namespace std;

namespace ndn
{

namespace security
{

  class SymmetricKey
  {
  public:
    
    SymmetricKey(const string & keyName)
      :m_keyName(keyName)
    {}
    
    virtual
    ~SymmetricKey() {}

    const string & getKeyName() const {return m_keyName;}    

    virtual string
    toStr() = 0;

    virtual Ptr<Blob>
    encrypt(const Blob & blob, EncryptMode em) = 0;

    virtual Ptr<Blob>
    decrypt(const Blob & blob, EncryptMode em) = 0;

  protected:
    const string m_keyName;
  };

}//security

}//ndn

#endif
