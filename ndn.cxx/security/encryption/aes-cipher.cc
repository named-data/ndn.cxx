/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "aes-cipher.h"

#include "ndn.cxx/security/exception.h"

#include <sstream>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/modes.h>

#include "logging.h"

INIT_LOGGER("ndn.security.CfbAesCipher");

using namespace std;

namespace ndn
{

namespace security
{
  AesCipher::AesCipher(const string & keyName, int keySize, int ivSize)
    :SymmetricKey(keyName),
     m_keySize(keySize),
     m_ivSize(ivSize)
  {
    CryptoPP::AutoSeededRandomPool rnd;
    m_key = new unsigned char[m_keySize];
    m_iv = new unsigned char[m_ivSize];
    
    rnd.GenerateBlock(m_key, m_keySize);
    rnd.GenerateBlock(m_iv, m_ivSize);
  }

  AesCipher::AesCipher(const string & keyName, const unsigned char * key, int keySize, const unsigned char * iv, int ivSize)
    :SymmetricKey(keyName),
     m_keySize(keySize),
     m_ivSize(ivSize)
  {
    m_key = new unsigned char[m_keySize];
    m_iv = new unsigned char[m_ivSize];
    
    memcpy(m_key, key, keySize);
    memcpy(m_iv, iv, ivSize);
  }

  AesCipher::~AesCipher()
  {
    delete [] m_key;
    delete [] m_iv;
  }

  string
  AesCipher::toStr()
  { return string(); }

  Ptr<AesCipher>
  AesCipher::fromStr(const string& str)
  { return NULL; }



  Ptr<Blob>
  AesCipher::encrypt(const Blob & blob, EncryptMode em)
  {
    string encryptedStr;

    if(em == EM_CFB_AES)
      {
        CryptoPP::CFB_Mode<AES>::Encryption encryption(m_key, m_keySize, m_iv);
        CryptoPP::StringSource(reinterpret_cast<const unsigned char *>(blob.buf()), blob.size(), true,
                               new CryptoPP::StreamTransformationFilter(encryption,
                                                                        new CryptoPP::StringSink(encryptedStr)
                                                                        ) // StreamTransformationFilter
                               );
      }
    else
      throw SecException("Encrypt Mode is not supported!");

    return Ptr<Blob>(new Blob(encryptedStr.c_str(), encryptedStr.size()));
  }
  
  Ptr<Blob>
  AesCipher::decrypt(const Blob & blob, EncryptMode em)
  {
    string decryptedStr;
 
    if(em == EM_CFB_AES)
      {
        CryptoPP::CFB_Mode<AES>::Decryption decryption(m_key, m_keySize, m_iv);
        CryptoPP::StringSource(reinterpret_cast<const unsigned char *>(blob.buf()), blob.size(), true,
                               new CryptoPP::StreamTransformationFilter(decryption,
                                                                     new CryptoPP::StringSink(decryptedStr)
                                                                     ) // StreamTransformationFilter
                               );
      }
    else
      throw SecException("Decrypt Mode is not supported!");

    return Ptr<Blob>(new Blob(decryptedStr.c_str(), decryptedStr.size()));;
  }

}//security

}//ndn
