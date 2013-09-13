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

#include "ndn.cxx/security/encryption/aes-cipher.h"
#include "ndn.cxx/security/exception.h"

#include <boost/filesystem.hpp>
#include <sstream>

#include "logging.h"

INIT_LOGGER("ndn.security.BasicEncryptionManager");

namespace fs = boost::filesystem;

namespace ndn
{

namespace security
{
  const string INIT_MKEY_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    MasterKey(                                                         \n \
        key_name  BLOB NOT NULL,                                       \n \
        key_type  INTEGER NOT NULL,                                    \n \
        active    BLOB NOT NULL,                                       \n \
                                                                       \
        PRIMARY KEY (key_name)                                 \n \
    );                                                                 \n \
  ";

  const string INIT_BC_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    BlockCipher(                                                       \n \
        key_name          BLOB NOT NULL,                               \n \
        key_type          INTEGER NOT NULL,                            \n \
        key_blob          BLOB NOT NULL,                               \n \
        encryption_type   INTEGER NOT NULL,                            \n \
        encryptkey_name   BLOB NOT NULL,                               \n \
                                                                       \
        PRIMARY KEY (key_name)                                         \n \
    );                                                                 \n \
                                                                       \
  CREATE INDEX blockcipher_index ON BlockCipher(key_name);             \n \
  ";

  BasicEncryptionManager::BasicEncryptionManager(Ptr<PrivatekeyStorage> privateStorage, const string & encryptionPath)
    :m_privateStorage(privateStorage)
  {
    
    int res = sqlite3_open(encryptionPath.c_str (), &m_db);

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

    //Check if MasterKey table exists;
    sqlite3_prepare_v2 (m_db, "SELECT name FROM sqlite_master WHERE type='table' And name='MasterKey'", -1, &stmt, 0);
    res = sqlite3_step (stmt);

    bool mkTableExist = false;
    if (res == SQLITE_ROW)
      mkTableExist = true;

    sqlite3_finalize (stmt);

    if(!mkTableExist)
      {
        char *errmsg = 0;
        res = sqlite3_exec (m_db, INIT_MKEY_TABLE.c_str (), NULL, NULL, &errmsg);
        
        if (res != SQLITE_OK && errmsg != 0)
          {
            _LOG_TRACE ("Init \"error\" in MasterKey: " << errmsg);
            sqlite3_free (errmsg);
          }
        
        ostringstream oss;
        oss << time::NowUnixTimestamp().total_seconds();
        string masterKeyName = "local-" + oss.str();
        m_defaultKeyName = masterKeyName;
        m_defaultSym = true;
          
        m_privateStorage->generateKey(masterKeyName);
        sqlite3_prepare_v2 (m_db, "INSERT INTO MasterKey (key_name, key_type, active) VALUES (?, ?, ?)", -1, &stmt, 0);
        sqlite3_bind_text (stmt, 1, masterKeyName.c_str(), masterKeyName.size(), SQLITE_TRANSIENT);
        sqlite3_bind_int (stmt, 2, 1);
        sqlite3_bind_int (stmt, 3, 1);
        sqlite3_step (stmt);
        sqlite3_finalize (stmt);    
      }
    else
      {
        sqlite3_prepare_v2 (m_db, "SELECT key_name, key_type FROM MasterKey WHERE active=1", -1, &stmt, 0);
        res = sqlite3_step (stmt);
        
        if (res == SQLITE_ROW)
          {
            m_defaultKeyName = string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)), sqlite3_column_bytes(stmt, 0));
            m_defaultSym = (sqlite3_column_int(stmt, 1) == 1) ? true : false;
          }
      }    
  }

  void 
  BasicEncryptionManager::createSymKey(const Name & keyName, KeyType keyType, const string & signkeyName, bool sym)
  {
    if(doesKeyNameExist(keyName.toUri()))
      throw SecException("Key exists!");
    
    // ostringstream oss;
    // oss << time::NowUnixTimestamp().total_seconds();
    // string keySeq = oss.str();


    Ptr<SymmetricKey> symKeyPtr = NULL;
    switch(keyType)
    {
    case KEY_TYPE_AES:
      symKeyPtr = Ptr<AesCipher>(new AesCipher(keyName.toUri()));
      break;
    default:
      throw SecException("Unsupported KeyType!");
    }
    
    string xmlStr = symKeyPtr->toXmlStr();
    
    string encryptName; 
    bool encryptSym;
    if(signkeyName.empty())
      {
        encryptName = m_defaultKeyName;
        encryptSym = m_defaultSym;
      }
    else
      {
        encryptName = signkeyName;
        encryptSym = sym;
      }

    Ptr<Blob> keyBlobPtr = NULL;
    if(encryptSym)
      {
        Ptr<Blob> encryptedKeyPtr = m_privateStorage->encrypt(encryptName, Blob(xmlStr.c_str(), xmlStr.size()), encryptSym);
        keyBlobPtr = encryptedKeyPtr;
      }
    else
      {
        //TODO:
        throw SecException("Do not support asymmetric key encryption at this moment!");
      }
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "INSERT INTO BlockCipher (key_name, key_type, key_blob, encryption_type, encryptkey_name)\
                               VALUES (?, ?, ?, ?, ?)", -1, &stmt, 0);
    
    sqlite3_bind_text(stmt, 1, keyName.toUri().c_str(), keyName.toUri().size(), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 2, keyType);
    sqlite3_bind_blob(stmt, 3, keyBlobPtr->buf(), keyBlobPtr->size(), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 4, (encryptSym ? 1 : 0));
    sqlite3_bind_text(stmt, 5, encryptName.c_str(), encryptName.size(), SQLITE_TRANSIENT);
    
    int res = sqlite3_step (stmt);
 
    sqlite3_finalize (stmt);
  }

  bool
  BasicEncryptionManager::doesKeyNameExist(const string & keyName)
  {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT count(*) FROM BlockCipher WHERE key_name=?", -1, &stmt, 0);
    
    sqlite3_bind_text(stmt, 1, keyName.c_str(), keyName.size(), SQLITE_TRANSIENT);
    
    int res = sqlite3_step (stmt);

    bool keyNameExist = false;
    if (res == SQLITE_ROW)
      {
        int countAll = sqlite3_column_int (stmt, 0);
        if (countAll > 0)
          keyNameExist = true;
      }
 
    sqlite3_finalize (stmt);

    return keyNameExist;
  }

  // bool
  // BasicEncryptionManager::doesEntryExist(const string & keyName, const string & keySeq)
  // {
  //   sqlite3_stmt *stmt;
  //   sqlite3_prepare_v2 (m_db, "SELECT count(*) FROM BlockCipher WHERE key_name=? AND key_seq=datetime(?, 'unixepoch')", -1, &stmt, 0);
    
  //   sqlite3_bind_text(stmt, 1, keyName.c_str(), keyName.size(), SQLITE_TRANSIENT);
  //   sqlite3_bind_tex(stmt, 2, keySeq.c_str(), keySeq.size(), SQLITE_TRANSIENT);

  //   int res = sqlite3_step (stmt);

  //   bool keyNameExist = false;
  //   if (res == SQLITE_ROW)
  //     {
  //       int countAll = sqlite3_column_int (stmt, 0);
  //       if (countAll > 0)
  //         keyNameExist = true;
  //     }
 
  //   sqlite3_finalize (stmt);

  //   return keyNameExist;
  // }


  Ptr<SymmetricKey>
  BasicEncryptionManager::getSymmetricKey(const string & keyName)
  {
    Ptr<SymmetricKey> keyPtr = NULL;

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT key_blob, key_type, encryption_type, encryptkey_name FROM BlockCipher WHERE key_name=?", -1, &stmt, 0);
    sqlite3_bind_text(stmt, 1, keyName.c_str(), keyName.size(), SQLITE_TRANSIENT);
    // sqlite3_prepare_v2 (m_db, "SELECT key_blob, key_type, encryption_type, encryptkey_name FROM BlockCipher", -1, &stmt, 0);
    

    
    int res = sqlite3_step (stmt);

    if (res == SQLITE_ROW)
      {
        Blob encryptedKeyBlob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes (stmt, 0));
        KeyType keyType = static_cast<KeyType>(sqlite3_column_int(stmt, 1));
        bool encryptSym = (sqlite3_column_int(stmt, 2) == 1 ? true : false);
        string encryptKey(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 3)), sqlite3_column_bytes (stmt, 3));
        
        if(encryptSym)
          {
            Ptr<Blob> keyBlobPtr = m_privateStorage->decrypt(encryptKey, encryptedKeyBlob, true);
            if(KEY_TYPE_AES == keyType)
              {
                Ptr<SymmetricKey> tmpKeyPtr = AesCipher::fromXmlStr(string(keyBlobPtr->buf(), keyBlobPtr->size()));
                if(tmpKeyPtr->getKeyName() == keyName)
                  keyPtr = tmpKeyPtr;
              }
            else
              throw SecException("Unsupported KeyType!");
          }
        else
          {
            //TODO:
            throw SecException("Do not support asymmetric key encryption at this moment!");
          }
      }
 
    sqlite3_finalize (stmt);

    return keyPtr;
    
  }

  Ptr<Blob>
  BasicEncryptionManager::encrypt(const Name & keyName, const Blob & blob, bool sym, EncryptMode em)
  {
    if(sym)
      {
        Ptr<SymmetricKey> keyPtr = getSymmetricKey(keyName.toUri());
        return keyPtr->encrypt(blob, em);
      }
    else
      return m_privateStorage->encrypt(keyName.toUri(), blob, false);

  }

  Ptr<Blob>
  BasicEncryptionManager::decrypt(const Name & keyName, const Blob & blob, bool sym, EncryptMode em)
  {
    if(sym)
      {
        Ptr<SymmetricKey> keyPtr = getSymmetricKey(keyName.toUri());
        return keyPtr->decrypt(blob, em);
      }
    else
      return m_privateStorage->decrypt(keyName.toUri(), blob, false);
  }
  

}//security

}//ndn
