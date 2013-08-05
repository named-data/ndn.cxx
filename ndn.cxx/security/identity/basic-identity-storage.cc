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

#include "ndn.cxx/security/exception.h"

#include <boost/filesystem.hpp>
#include <stdlib.h>


#include "logging.h"

INIT_LOGGER ("BasicIdentityStorage");

using namespace std;
namespace fs = boost::filesystem;

namespace ndn
{

namespace security
{

  const string INIT_KEY_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    Key(                                                               \n \
        identity_name     BLOB NOT NULL,                               \n \
        key_identifier    BLOB NOT NULL,                               \n \
        key_type          INTEGER,                                     \n \
        public_key        BLOB,                                        \n \
                                                                       \
        PRIMARY KEY (identity_name, key_identifier)                    \n \
    );                                                                 \n \
  CREATE INDEX identity_name ON Key(identity_name);                    \n \
  ";

  const string INIT_CERT_TABLE = "\
  CREATE TABLE IF NOT EXISTS                                           \n \
    IdentityCertificate(                                               \n \
        cert_name         BLOB NOT NULL,                               \n \
        cert_issuer       BLOB NOT NULL,                               \n \
        identity_name     BLOB NOT NULL,                               \n \
        not_before        TEXT,                                        \n \
        not_after         TEXT,                                        \n \
                                                                       \
        PRIMARY KEY (cert_name)                                        \n \
    );                                                                 \n \
  CREATE INDEX cert ON IdentityCertificate(cert_name);            \n \
  CREATE INDEX subject ON IdentityCertificate(identity_name);    \n \
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

    char *errmsg = 0;
    // res = sqlite3_exec (m_db, INIT_KEY_TABLE.c_str (), NULL, NULL, &errmsg);
    // res = sqlite3_exec (m_db, INIT_CERT_TABLE.c_str (), NULL, NULL, &errmsg);

    if (res != SQLITE_OK && errmsg != 0)
    {
      _LOG_TRACE ("Init \"error\": " << errmsg);
      sqlite3_free (errmsg);
    }
  }


  bool 
  BasicIdentityStorage::doesIdentityExist (const Name & identity)
  {
    bool result = false;
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (m_db, "SELECT count(*) FROM key WHERE identity_name=?", -1, &stmt, 0);

    _LOG_DEBUG("identity: " << identity.toUri());

    sqlite3_bind_blob(stmt, 1, identity.toUri().c_str(),  identity.toUri().size (), SQLITE_TRANSIENT);
    int res = sqlite3_step (stmt);

    if (res == SQLITE_ROW)
      {
        int countAll = sqlite3_column_int (stmt, 0);
        _LOG_DEBUG("countAll: " << countAll);
        if (countAll > 0)
          result = true;
      }
    sqlite3_finalize (stmt);

    return result;
  }

  bool 
  BasicIdentityStorage::revokeIdentity ()
  {
    //TODO:
    return false;
  }

  bool 
  BasicIdentityStorage::addCertificate ()
  {
    //TODO:
    return false;
  }

  Name 
  BasicIdentityStorage::getNewKeyName (const Name & identity)
  {
    //TODO:
    return Name();
  }

  bool 
  BasicIdentityStorage::doesKeyExist (const Name & keyName)
  {
    //TODO:
    return false;
  }

  bool 
  BasicIdentityStorage::addKey (const Name & identity, const Name & keyName, Ptr<Blob> digest, Time ts)
  {
    //TODO:
    return true;
  }

  bool 
  BasicIdentityStorage::activateKey (const string & identity, const string & keyID)
  {
    //TODO:
    return false;
  }

  bool
  BasicIdentityStorage::deactivateKey (const string & identity, const string & keyID)
  {
    //TODO:
    return false;
  }

  bool 
  BasicIdentityStorage::addCertificate (const Certificate & certificate)
  {
    //TODO:
    return false;
  }

  Ptr<Certificate> 
  BasicIdentityStorage::getCertificate (const Name & certName)
  {
    //TODO:
    return NULL;
  }

  string 
  BasicIdentityStorage::getKeyNameForCert (const Name & certName, const int & certSeq)
  {
    //TODO:
    return "";
  }

  Name 
  BasicIdentityStorage::getDefaultIdentity ()
  {
    //TODO:
    return Name();
  }

  Name 
  BasicIdentityStorage::getDefaultKeyName (const Name & identity)
  {
    //TODO:
    return Name();
  }
    
  Name 
  BasicIdentityStorage::getDefaultCertNameForIdentity (const Name & identity)
  {
    //TODO:
    return Name();
  }

  Name 
  BasicIdentityStorage::getDefaultCertNameForKey (const Name & keyName)
  {
    //TODO:
    return Name();
  }

  void 
  BasicIdentityStorage::setDefaultIdentity (const Name & identity)
  {
    //TODO:
  }

  void 
  BasicIdentityStorage::setDefaultKeyName (const Name & identity, const Name & keyName)
  {
    //TODO:
  }

  void 
  BasicIdentityStorage::setDefaultCertName (const Name & keyName, const Name & certName)
  {
    //TODO:
  }

}//security

}//ndn
