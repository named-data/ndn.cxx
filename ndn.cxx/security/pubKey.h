/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef KEYCHAIN_PUBKEY_H
#define KEYCHAIN_PUBKEY_H

#include <string>

#include "ndn.cxx/security/security-common.h"

using namespace std;

namespace ndn
{

namespace keychain 
{
  class PubKey{
  public:

    PubKey(string keyName, int keyType, Ptr<Blob> keyLabel, Ptr<Blob> keyBits) {
      m_keyName = keyName;
      m_keyType = keyType;
      m_keyLabel = keyLabel;
      m_keyBits = keyBits;
    }
    
    virtual ~PubKey();

    virtual string getKeyName() {return m_keyName;}

    virtual int getKey() { return m_keyType;}

    virtual Ptr<Blob> getKeyLabel() {return m_keyLabel;}
    
    virtual Ptr<Blob> getKeyBits() {return m_keyBits;}

    virtual int getKeySize() {return m_keyBits->size();}
    
  private:
    string m_keyName;
    int m_keyType;
    Ptr<Blob> m_keyLabel;
    Ptr<Blob> m_keyBits;
  };

} //keychain

} //ndn
#endif
