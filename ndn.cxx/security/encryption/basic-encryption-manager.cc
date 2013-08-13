/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "basic-encryption-manager.h"

#include <boost/filesystem.hpp>

#include "logging.h"

INIT_LOGGER("ndn.security.BasicEncryptionManager");

namespace fs = boost::filesystem;

namespace ndn
{

namespace security
{
  const string INIT_BC_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    BlockCipher(                                                       \n \
        key_name          BLOB NOT NULL,                               \n \
        key_seq           BLOB NOT NULL,                               \n \
        key_type          INTEGER NOT NULL,                            \n \
        block_size        INTEGER NOT NULL,                            \n \
        block             BLOB NOT NULL,                               \n \
        key_size          INTEGER NOT NULL,                            \n \
        key               BLOB NOT NULL,                               \n \
                                                                       \
        PRIMARY KEY (key_name, key_seq)                                \n \
    );                                                                 \n \
                                                                       \
  CREATE INDEX blockcipher_index ON BlockCipher(key_name);             \n \
  ";

  BasicEncryptionManager::BasicEncryptionManager(Ptr<PrivatekeyStore> privateStorage)
    :m_privateStorage(privateStorage)
  {
    fs::path identityDir = fs::path(getenv("HOME")) / ".ndn-identity";
    fs::create_directories (identityDir);
    
    int res = sqlite3_open((identityDir / "encryption.db").c_str (), &m_db);

    if (res != SQLITE_OK)
      {
        throw SecException("identity DB cannot be open/created");
      }

    //Check if BLOCKCIPHER table exists;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT name FROM sqlite_master WHERE type='table' And name='BlockCipher'", -1, &stmt, 0);
    res = sqlite3_step (stmt);

    bool bcTableExist = false;
    if (res == SQLITE_ROW)
      bcTableExist = true;

    sqlite3_finalize (stmt);

    if(!bcTableExist)
      {
        char *errmsg = 0;
        res = sqlite3_exec (m_db, INIT_BC_TABLE.c_str (), NULL, NULL, &errmsg);
        
        if (res != SQLITE_OK && errmsg != 0)
          {
            _LOG_TRACE ("Init \"error\" in BlockCipher: " << errmsg);
            sqlite3_free (errmsg);
          }
      }
  }
  void 
  BasicEncryptionManager::CreateKey(const Name & keyName, KeyType keyType)
  {
    //TODO:
  }

  void
  BasicEncryptionManager::InstallKey(const Name & keyName, const Blob & blob)
  {
  }
    
  Ptr<Blob>
  BasicEncryptionManager::Encrypt(const Publickey & publicKey, const Blob & blob)
  {
    return NULL;
  }

  Ptr<Blob>
  BasicEncryptionManager::Encrypt(const Name & keyName, const Blob & blob)
  {
    return NULL;
  }

  Ptr<Blob>
  BasicEncryptionManager::Decrypt(const Name & keyName, const Blob & blob, bool sym)
  {
    return NULL;
  }
  

}//security

}//ndn
