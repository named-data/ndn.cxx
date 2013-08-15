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
#include <tinyxml.h>

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
  AesCipher::toXmlStr()
  {
    TiXmlDocument cipherDoc;
    TiXmlElement * cipher = new TiXmlElement("CFB_AES_CIPHER");
    cipherDoc.LinkEndChild(cipher);

    TiXmlElement * keyName = new TiXmlElement("KEYNAME");
    cipher->LinkEndChild(keyName);
    TiXmlText * keyNameText = new TiXmlText(m_keyName);
    keyName->LinkEndChild(keyNameText);

    TiXmlElement * key = new TiXmlElement("KEY");
    cipher->LinkEndChild(key);    
    string encodedKey;
    CryptoPP::StringSource kss(m_key, m_keySize, true,
                              new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedKey)));
    TiXmlText * keyText = new TiXmlText(encodedKey);
    key->LinkEndChild(keyText);

    TiXmlElement * iv = new TiXmlElement("IV");
    cipher->LinkEndChild(iv);
    string encodedIv;
    CryptoPP::StringSource iss(m_iv, m_ivSize, true,
                               new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encodedIv)));
    TiXmlText * ivText = new TiXmlText(encodedIv);
    iv->LinkEndChild(ivText);
    
    ostringstream oss;
    oss << cipherDoc;

    return oss.str();
  }

  Ptr<AesCipher>
  AesCipher::fromXmlStr(const string & str)
  {
    string base64Key;
    string base64Iv;
    string keyName;

    TiXmlDocument cipherDoc;
    cipherDoc.Parse(str.c_str());

    TiXmlNode * cipher = cipherDoc.FirstChild();

    if(cipher->ValueStr() != string("CFB_AES_CIPHER"))
      return NULL;
    
    TiXmlNode * it = cipher->FirstChild();
    while(it != NULL)
      {
        if(it->ValueStr() == string("KEYNAME"))
          keyName = it->FirstChild()->ValueStr();
        if(it->ValueStr() == string("KEY"))
          base64Key = it->FirstChild()->ValueStr();
        if(it->ValueStr() == string("IV"))
          base64Iv = it->FirstChild()->ValueStr();
        it = it->NextSibling();
      }
    string key;
    CryptoPP::StringSource ks(reinterpret_cast<const unsigned char *>(base64Key.c_str()), base64Key.size(), true,
                              new CryptoPP::Base64Decoder(new CryptoPP::StringSink(key)));
    string iv;
    CryptoPP::StringSource is(reinterpret_cast<const unsigned char *>(base64Iv.c_str()), base64Iv.size(), true,
                              new CryptoPP::Base64Decoder(new CryptoPP::StringSink(iv)));

    
    return Ptr<AesCipher>(new AesCipher(keyName,
                                        reinterpret_cast<const unsigned char *>(key.c_str()), 
                                        key.size(), 
                                        reinterpret_cast<const unsigned char *>(iv.c_str()),
                                        iv.size()));
  }

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
