/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "dump-certificate.h"

#include <sqlite3.h>
#include <string>

using namespace std;

namespace ndn
{

namespace security
{
  DumpCertificate::DumpCertificate()
  {
  }
  
  void
  DumpCertificate::dump()
  {
    sqlite3 * dbFrom;
    sqlite3 * dbTo;

    sqlite3_open("/Users/yuyingdi/.ndn-identity/identity.db", &dbFrom);
    sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &dbTo);

    string INIT_DATA_TABLE = "\
      CREATE TABLE IF NOT EXISTS                                           \n \
        Data(                                                              \n \
          data_name     BLOB NOT NULL,                                     \n \
          data_blob     BLOB NOT NULL,                                     \n \
                                                                           \
        PRIMARY KEY (data_name)                                            \n \
    );";

    char *errmsg = 0;
    sqlite3_exec (dbTo, INIT_DATA_TABLE.c_str (), NULL, NULL, &errmsg);
    
    sqlite3_stmt * stmtFrom;
    sqlite3_prepare_v2(dbFrom, "SELECT cert_name, certificate_data FROM Certificate", -1, &stmtFrom, 0);
    
    while(sqlite3_step(stmtFrom) == SQLITE_ROW)
      {
	sqlite3_stmt * stmtTo;
	sqlite3_prepare_v2(dbTo, "INSERT INTO data (data_name, data_blob) VALUES (?, ?)", -1, &stmtTo, 0);
	
	sqlite3_bind_text(stmtTo, 1, reinterpret_cast<const char *>(sqlite3_column_text(stmtFrom, 0)), sqlite3_column_bytes(stmtFrom, 0), SQLITE_TRANSIENT);
	sqlite3_bind_blob(stmtTo, 2, sqlite3_column_blob(stmtFrom, 1), sqlite3_column_bytes(stmtFrom, 1), SQLITE_TRANSIENT);

	sqlite3_step(stmtTo);

	sqlite3_finalize(stmtTo);
      }

    sqlite3_finalize(stmtFrom);
  }

}//security

}//ndn
