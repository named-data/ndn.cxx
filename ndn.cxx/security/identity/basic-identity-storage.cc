/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "basic-identity-storage.h"

#include "ndn.cxx/fields/signature-sha256-with-rsa.h"

#include "ndn.cxx/regex/regex.h"

#include "ndn.cxx/security/exception.h"

#include <boost/filesystem.hpp>

#include <stdlib.h>
#include <sstream>
#include <fstream>


#include "logging.h"

INIT_LOGGER ("BasicIdentityStorage");

using namespace std;
namespace fs = boost::filesystem;

namespace ndn
{

namespace security
{
  const string INIT_ID_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    Identity(                                                          \n \
        identity_name     BLOB NOT NULL,                               \n \
        default_identity  INTEGER DEFAULT 0,                           \n \
                                                                       \
        PRIMARY KEY (identity_name)                                    \n \
    );                                                                 \n \
                                                                       \
  CREATE INDEX identity_index ON Identity(identity_name);              \n \
  ";

  const string INIT_KEY_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    Key(                                                               \n \
        identity_name     BLOB NOT NULL,                               \n \
        key_identifier    BLOB NOT NULL,                               \n \
        key_type          INTEGER,                                     \n \
        public_key        BLOB,                                        \n \
        default_key       INTEGER DEFAULT 0,                           \n \
        active            INTEGER DEFAULT 0,                           \n \
                                                                       \
        PRIMARY KEY (identity_name, key_identifier)                    \n \
    );                                                                 \n \
                                                                       \
  CREATE INDEX key_index ON Key(identity_name);                        \n \
  ";

  const string INIT_CERT_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    Certificate(                                                       \n \
        cert_name         BLOB NOT NULL,                               \n \
        cert_issuer       BLOB NOT NULL,                               \n \
        identity_name     BLOB NOT NULL,                               \n \
        key_identifier    BLOB NOT NULL,                               \n \
        not_before        TIMESTAMP,                                   \n \
        not_after         TIMESTAMP,                                   \n \
        certificate_data  BLOB NOT NULL,                               \n \
        valid_flag        INTEGER DEFAULT 0,                           \n \
        default_cert      INTEGER DEFAULT 0,                           \n \
                                                                       \
        PRIMARY KEY (cert_name)                                        \n \
    );                                                                 \n \
                                                                       \
  CREATE INDEX cert_index ON Certificate(cert_name);           \n \
  CREATE INDEX subject ON Certificate(identity_name);          \n \
  ";

  BasicIdentityStorage::BasicIdentityStorage()
  {
    fs::path identityDir = fs::path(getenv("HOME")) / ".ndn-identity";
    fs::create_directories (identityDir);
    
    int res = sqlite3_open((identityDir / "identity.db").c_str (), &m_db);

    if (res != SQLITE_OK)
      {
        throw SecException("identity DB cannot be open/created");
      }

    //Check if Key table exists;
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT name FROM sqlite_master WHERE type='table' And name='Identity'", -1, &stmt, 0);
    res = sqlite3_step (stmt);

    bool idTableExist = false;
    if (res == SQLITE_ROW)
      idTableExist = true;

    sqlite3_finalize (stmt);

    if(!idTableExist)
      {
        char *errmsg = 0;
        res = sqlite3_exec (m_db, INIT_ID_TABLE.c_str (), NULL, NULL, &errmsg);
        
        if (res != SQLITE_OK && errmsg != 0)
          {
            _LOG_TRACE ("Init \"error\" in Identity: " << errmsg);
            sqlite3_free (errmsg);
          }
      }

    //Check if Key table exists;
    sqlite3_prepare_v2 (m_db, "SELECT name FROM sqlite_master WHERE type='table' And name='Key'", -1, &stmt, 0);
    res = sqlite3_step (stmt);

    bool keyTableExist = false;
    if (res == SQLITE_ROW)
      keyTableExist = true;

    sqlite3_finalize (stmt);

    if(!keyTableExist)
      {
        char *errmsg = 0;
        res = sqlite3_exec (m_db, INIT_KEY_TABLE.c_str (), NULL, NULL, &errmsg);
        
        if (res != SQLITE_OK && errmsg != 0)
          {
            _LOG_TRACE ("Init \"error\" in KEY: " << errmsg);
            sqlite3_free (errmsg);
          }
      }

    //Check if Certificate table exists;
    sqlite3_prepare_v2 (m_db, "SELECT name FROM sqlite_master WHERE type='table' And name='Certificate'", -1, &stmt, 0);
    res = sqlite3_step (stmt);

    bool idCertTableExist = false;
    if (res == SQLITE_ROW)
      idCertTableExist = true;
    
    sqlite3_finalize (stmt);

    if(!idCertTableExist)
      {
        char *errmsg = 0;
        res = sqlite3_exec (m_db, INIT_CERT_TABLE.c_str (), NULL, NULL, &errmsg);
        
        if (res != SQLITE_OK && errmsg != 0)
          {
            _LOG_TRACE ("Init \"error\" in ID-CERT: " << errmsg);
            sqlite3_free (errmsg);
          }
      }
  }

  bool 
  BasicIdentityStorage::doesIdentityExist (const Name & identity)
  {
    bool result = false;
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT count(*) FROM Identity WHERE identity_name=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    int res = sqlite3_step (stmt);
    
    if (res == SQLITE_ROW)
      {
        int countAll = sqlite3_column_int (stmt, 0);
        if (countAll > 0)
          result = true;
      }
 
    sqlite3_finalize (stmt);

    return result;
  }

  void 
  BasicIdentityStorage::addIdentity (const Name & identity)
  {
    sqlite3_stmt *stmt;

    sqlite3_prepare_v2 (m_db, "INSERT INTO Identity (identity_name) values (?)", -1, &stmt, 0);
        
    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    
    int res = sqlite3_step (stmt);
    
    sqlite3_finalize (stmt);
  }

  bool 
  BasicIdentityStorage::revokeIdentity ()
  {
    //TODO:
    return false;
  }

  Name 
  BasicIdentityStorage::getNewKeyName(const Name & identity, bool ksk)
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

  bool 
  BasicIdentityStorage::doesKeyExist (const Name & keyName)
  {
    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT count(*) FROM Key WHERE identity_name=? AND key_identifier=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(),  keyId.size (), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    bool keyIdExist = false;
    if (res == SQLITE_ROW)
      {
        int countAll = sqlite3_column_int (stmt, 0);
        if (countAll > 0)
          keyIdExist = true;
      }
 
    sqlite3_finalize (stmt);

    return keyIdExist;
  }

  Name 
  BasicIdentityStorage::getKeyNameForCert (const Name & certName)
  {
    int i = certName.size() - 1;

    for (; i >= 0; i--)
      {
        if(certName.get(i).toUri() == string("ID-CERT"))
          break; 
      }
    
    return certName.getSubName(0, i);
  }

  void
  BasicIdentityStorage::addKey (const Name & keyName, KeyType keyType, Ptr<Blob> pubKeyBlob)
  {
    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);


    if(!doesIdentityExist(identity))
      addIdentity(identity);

    if(doesKeyExist(keyName))
      throw SecException("key with the same name has already existed!");

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "INSERT INTO Key (identity_name, key_identifier, key_type, public_key) values (?, ?, ?, ?)", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(),  keyId.size (), SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, (int)keyType);
    sqlite3_bind_blob(stmt, 4, pubKeyBlob->buf(), pubKeyBlob->size(), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    sqlite3_finalize (stmt);
  }

  Ptr<Blob>
  BasicIdentityStorage::getKey (const Name & keyName)
  {
    if(!doesKeyExist(keyName))
      {
        _LOG_DEBUG("keyName does not exist");
        return NULL;
      }

    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT public_key FROM Key WHERE identity_name=? AND key_identifier=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(),  keyId.size (), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    Ptr<Blob> result = NULL;
    if(res == SQLITE_ROW)
      {
        result = Ptr<Blob>(new Blob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes (stmt, 0)));
      }

    sqlite3_finalize (stmt);

    return result;
  }

  void 
  BasicIdentityStorage::activateKey (const Name & keyName)
  {
    updateKeyStatus(keyName, true);
  }

  void 
  BasicIdentityStorage::deactivateKey (const Name & keyName)
  {
    updateKeyStatus(keyName, false);
  }

  void 
  BasicIdentityStorage::updateKeyStatus(const Name & keyName, bool active)
  {
    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "UPDATE Key SET active=? WHERE identity_name=? AND key_identifier=?", -1, &stmt, 0);

    sqlite3_bind_int(stmt, 1, (active ? 1 : 0));
    sqlite3_bind_text(stmt, 2, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, keyId.c_str(),  keyId.size (), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    sqlite3_finalize (stmt);
  }


  bool
  BasicIdentityStorage::doesCertificateExist (const Name & certName)
  {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT count(*) FROM Certificate WHERE cert_name=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, certName.toUri().c_str(),  certName.toUri().size (), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    bool certExist = false;
    if (res == SQLITE_ROW)
      {
        int countAll = sqlite3_column_int (stmt, 0);
        if (countAll > 0)
          certExist = true;
      }
 
    sqlite3_finalize (stmt);
    
    return certExist;
  }

  void 
  BasicIdentityStorage::addCertificate (const Certificate & certificate)
  {
    const Name & certName = certificate.getName();
    Name keyName = getKeyNameForCert(certName);

    if(!doesKeyExist(keyName))
      throw SecException("No corresponding Key record for certificaite!");
    
    // Check if certificate has already existed!
    if(doesCertificateExist(certName))
      throw SecException("Certificate has already been installed!");

    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);
    
    // Check if the public key of certificate is the same as the key record
   
    Ptr<Blob> keyBlob = getKey(keyName);
    
    if(keyBlob == NULL or (*keyBlob) != (*certificate.getPublicKeyInfo().getKeyBlob()))
      throw SecException("Certificate does not match public key!");

    // Insert the certificate
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, 
                        "INSERT INTO Certificate (cert_name, cert_issuer, identity_name, key_identifier, not_before, not_after, certificate_data)\
                         values (?, ?, ?, ?, datetime(?, 'unixepoch'), datetime(?, 'unixepoch'), ?)",
                        -1, &stmt, 0);

    _LOG_DEBUG("certName: " << certName.toUri().c_str());
    sqlite3_bind_text(stmt, 1, certName.toUri().c_str(), certName.toUri().size(),  SQLITE_TRANSIENT);

    Ptr<const signature::Sha256WithRsa> signature = boost::dynamic_pointer_cast<const signature::Sha256WithRsa>(certificate.getSignature());
    const Name & signerName = signature->getKeyLocator().getKeyName();
    sqlite3_bind_text(stmt, 2, signerName.toUri().c_str(),  signerName.toUri().size (),  SQLITE_TRANSIENT);

    sqlite3_bind_text(stmt, 3, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, keyId.c_str(),  keyId.size (), SQLITE_TRANSIENT);

    sqlite3_bind_int64(stmt, 5, (sqlite3_int64)(certificate.getNotBefore() - time::UNIX_EPOCH_TIME).total_seconds());
    sqlite3_bind_int64(stmt, 6, (sqlite3_int64)(certificate.getNotAfter() - time::UNIX_EPOCH_TIME).total_seconds());

    Ptr<Blob> certBlob = certificate.encodeToWire();

    sqlite3_bind_blob(stmt, 7, certBlob->buf(), certBlob->size(), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    sqlite3_finalize (stmt);
  }

  Ptr<Data> 
  BasicIdentityStorage::getCertificate (const Name & certName, bool any)
  {
    if(doesCertificateExist(certName))
      {
        sqlite3_stmt *stmt;
        if(!any)
          {
            sqlite3_prepare_v2 (m_db, 
                                "SELECT certificate_data FROM Certificate \
                                 WHERE cert_name=? AND not_before<datetime(?, 'unixepoch') AND not_after>datetime(?, 'unixepoch') and valid_flag=1",
                                -1, &stmt, 0);
            
            sqlite3_bind_text(stmt, 1, certName.toUri().c_str(), certName.toUri().size(), SQLITE_TRANSIENT);
            sqlite3_bind_int64(stmt, 2, (sqlite3_int64)time::NowUnixTimestamp().total_seconds());
            sqlite3_bind_int64(stmt, 3, (sqlite3_int64)time::NowUnixTimestamp().total_seconds());
          }
        else
          {
            sqlite3_prepare_v2 (m_db, 
                                "SELECT certificate_data FROM Certificate WHERE cert_name=?", -1, &stmt, 0);

            sqlite3_bind_text(stmt, 1, certName.toUri().c_str(), certName.toUri().size(), SQLITE_TRANSIENT);
          }
        
        int res = sqlite3_step (stmt);
        
        Ptr<Data> data = NULL;


        if (res == SQLITE_ROW)
          {
            data = Data::decodeFromWire(Ptr<Blob>(new Blob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes (stmt, 0))));            
          }
        sqlite3_finalize (stmt);
        
        return data;
      }
    else
      {
        _LOG_DEBUG("Certificate does not exist!");
        return NULL;
      }
  }

  Name 
  BasicIdentityStorage::getDefaultIdentity ()
  {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT identity_name FROM Identity WHERE default_identity=1", -1, &stmt, 0);

    int res = sqlite3_step (stmt);
        
    Name identity;

    if (res == SQLITE_ROW)
      identity = Name(string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)), sqlite3_column_bytes (stmt, 0)));
 
    sqlite3_finalize (stmt);
        
    return identity;
  }

  Name 
  BasicIdentityStorage::getDefaultKeyName (const Name & identity)
  {
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT key_identifier FROM Key WHERE identity_name=? AND default_key=1", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);
        
    Name keyName;

    if (res == SQLITE_ROW)
      keyName = Name(identity).append(string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)), sqlite3_column_bytes (stmt, 0)));
 
    sqlite3_finalize (stmt);
        
    return keyName;
  }
    
  Name 
  BasicIdentityStorage::getDefaultCertNameForIdentity (const Name & identity)
  {
    Name keyName = getDefaultKeyName(identity);

    return getDefaultCertNameForKey(keyName);
  }

  Name 
  BasicIdentityStorage::getDefaultCertNameForKey (const Name & keyName)
  {
    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT cert_name FROM Certificate WHERE identity_name=? AND key_identifier=? AND default_cert=1", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(), keyId.size(), SQLITE_TRANSIENT);

    int res = sqlite3_step (stmt);

    Name certName;

    if (res == SQLITE_ROW)
      certName = Name(string(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)), sqlite3_column_bytes (stmt, 0)));
 
    sqlite3_finalize (stmt);
        
    return certName;
  }

  void 
  BasicIdentityStorage::setDefaultIdentity (const Name & identity)
  {
    sqlite3_stmt *stmt;

    //Reset previous default identity
    sqlite3_prepare_v2 (m_db, "UPDATE Identity SET default_identity=0 WHERE default_identity=1", -1, &stmt, 0);

    while( sqlite3_step (stmt) == SQLITE_ROW)
      {}
    
    sqlite3_finalize (stmt);

    //Set current default identity
    sqlite3_prepare_v2 (m_db, "UPDATE Identity SET default_identity=1 WHERE identity_name=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);
    
    sqlite3_step (stmt);

    sqlite3_finalize (stmt);
  }

  void 
  BasicIdentityStorage::setDefaultKeyName (const Name & keyName)
  {
    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);

    sqlite3_stmt *stmt;

    //Reset previous default Key
    sqlite3_prepare_v2 (m_db, "UPDATE Key SET default_key=0 WHERE default_key=1 and identity_name=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);

    while( sqlite3_step (stmt) == SQLITE_ROW)
      {}
    
    sqlite3_finalize (stmt);

    //Set current default Key
    sqlite3_prepare_v2 (m_db, "UPDATE Key SET default_key=1 WHERE identity_name=? AND key_identifier=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(), keyId.size(), SQLITE_TRANSIENT);
    
    sqlite3_step (stmt);

    sqlite3_finalize (stmt);
  }

  void 
  BasicIdentityStorage::setDefaultCertName (const Name & keyName, const Name & certName)
  {
    string keyId = keyName.get(-1).toUri();
    Name identity = keyName.getSubName(0, keyName.size() - 1);

    sqlite3_stmt *stmt;

    //Reset previous default Key
    sqlite3_prepare_v2 (m_db, "UPDATE Certificate SET default_cert=0 WHERE default_cert=1 AND identity_name=? AND key_identifier=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(), keyId.size(), SQLITE_TRANSIENT);

    while( sqlite3_step (stmt) == SQLITE_ROW)
      {}
    
    sqlite3_finalize (stmt);

    //Set current default Key
    sqlite3_prepare_v2 (m_db, "UPDATE Certificate SET default_cert=1 WHERE identity_name=? AND key_identifier=? AND cert_name=?", -1, &stmt, 0);

    sqlite3_bind_text(stmt, 1, identity.toUri().c_str(), identity.toUri().size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, keyId.c_str(), keyId.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, certName.toUri().c_str(), certName.toUri().size(), SQLITE_TRANSIENT);
    
    sqlite3_step (stmt);

    sqlite3_finalize (stmt);
  }

}//security

}//ndn
