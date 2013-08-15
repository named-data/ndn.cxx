/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_AES_CIPHER_H
#define NDN_AES_CIPHER_H

#include "symmetric-key.h"
#include <cryptopp/aes.h>

namespace ndn
{

namespace security
{
  typedef CryptoPP::AES AES;
  class AesCipher : public SymmetricKey
  {
  public:
    AesCipher(const string & keyName, int keySize = AES::DEFAULT_KEYLENGTH, int ivSize = AES::BLOCKSIZE);
    
    AesCipher(const string & keyName, const unsigned char * key, int keySize, const unsigned char * iv, int ivSize);
    
    virtual
    ~AesCipher();

    virtual string
    toXmlStr();

    static Ptr<AesCipher>
    fromXmlStr(const string & str);

    virtual Ptr<Blob>
    encrypt(const Blob & blob, EncryptMode em = EM_CFB_AES);

    virtual Ptr<Blob>
    decrypt(const Blob & blob, EncryptMode em = EM_CFB_AES);
    
  private:
    const int m_keySize;
    const int m_ivSize;
    unsigned char * m_key;
    unsigned char * m_iv;
  };

}//security

}//ndn

#endif
