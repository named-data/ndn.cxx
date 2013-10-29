/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Xingyu Ma (maxy12@cs.ucla.edu)
 */

#ifndef SIMPLEKEY_STORE_H
#define SIMPLEKEY_STORE_H

#include "ndn.cxx/common.h"

#include "privatekey-storage.h"
#include <boost/filesystem.hpp>

namespace ndn {
namespace security {

class SimpleKeyStore : public PrivatekeyStorage
{
public:
  SimpleKeyStore(const std::string & dir = "");
  /**
   * @brief destructor of PrivateKeyStore
   */
  virtual
  ~SimpleKeyStore() {};

  virtual void
  generateKeyPair(const Name & keyName, KeyType keyType = KEY_TYPE_RSA, int keySize = 2048);

  /**
   *
   */
  virtual Ptr<Publickey>
  getPublickey(const Name & keyName);

  /**
   * @brief sign data
   * @param keyName the name of the signing key
   * @param digestAlgo the digest algorithm
   * @param pData the pointer to data
   * @returns signature, NULL if signing fails
   */
  virtual Ptr<Blob>
  sign(const Blob & pData, const Name & keyName, DigestAlgorithm digestAlgo = DIGEST_SHA256);

  /**
   * @brief decrypt data
   * @param keyName the name of the decrypting key
   * @param pData the pointer to encrypted data
   * @returns decrypted data
   */
  virtual Ptr<Blob>
  decrypt(const Name & keyName, const Blob & pData, bool sym = false);

  virtual Ptr<Blob>
  encrypt(const Name & keyName, const Blob & pData, bool sym = false);


  //TODO Symmetrical key stuff.
  /**
   * @brief generate a symmetric keys
   * @param keyName the name of the key
   * @param keyType the type of the key, e.g. AES
   * @param keySize the size of the key
   * @returns true if key have been successfully generated
   */
  virtual void
  generateKey(const Name & keyName, KeyType keyType = KEY_TYPE_AES, int keySize = 256);

  virtual bool
  doesKeyExist(const Name & keyName, KeyClass keyClass);

  std::string
  nameTransform(const std::string &keyName, const std::string &extension);

private:
  Ptr<Blob>
  readSymetricKey(const std::string &filename);

  void maintainMapping(std::string str1, std::string str2);
  void
  writeSymetricKey(const std::string &filename, const Blob & pData);

private:
  boost::filesystem::path m_keystorePath;
};

}//security
}//ndn

#endif // SIMPLEKEY_STORE_H
