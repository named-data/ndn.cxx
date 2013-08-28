/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "fake-wrapper.h"

#include "executor/executor.h"
#include "ndn.cxx/security/keychain.h"

#include <boost/bind.hpp>
#include <sqlite3.h>

#include "logging.h"

INIT_LOGGER("ndn.FakeWrapper");

namespace ndn
{
  FakeWrapper::FakeWrapper(Ptr<security::Keychain> keychain)
    : m_executor (new Executor(1))
    , m_keychain (keychain)
  {
    // m_keychain->setFakeWrapper(this);
    m_executor->start();
  }

  FakeWrapper::~FakeWrapper()
  {
    m_executor->shutdown ();
  }

  void
  FakeWrapper::sendInterest(Ptr<Interest> interestPtr, Ptr<Closure> closurePtr)
  {    

    sqlite3 * fakeDB;
    int res = sqlite3_open("/Users/yuyingdi/Test/fake-data.db", &fakeDB);

    sqlite3_stmt *stmt;
    sqlite3_prepare_v2 (fakeDB, "SELECT data_blob FROM data WHERE data_name=?", -1, &stmt, 0);

    const Name & name = interestPtr->getName();
    
    sqlite3_bind_text(stmt, 1, name.toUri().c_str(), name.toUri().size(), SQLITE_TRANSIENT);

    res = sqlite3_step(stmt);

    
    if(res == SQLITE_ROW)
      {
        Ptr<Data> dataPtr = Data::decodeFromWire(Ptr<Blob>(new Blob(sqlite3_column_blob(stmt, 0), sqlite3_column_bytes(stmt, 0))));    
        _LOG_DEBUG("DataPtr: " << m_executor << " Name: " << name.toUri());
        m_executor->execute(boost::bind(&FakeWrapper::incomingData, this, dataPtr, interestPtr, closurePtr));
      }
    else
      {
        m_executor->execute(boost::bind(closurePtr->m_timeoutCallback, closurePtr, interestPtr));
      }
    res = sqlite3_close (fakeDB);

  }

  void
  FakeWrapper::incomingData(Ptr<Data> dataPtr, Ptr<Interest> interestPtr, Ptr<Closure> closurePtr)
  {
    if(closurePtr->m_unverifiedDataCallback.empty())
      m_keychain->verifyData(dataPtr, 
                             boost::bind(&FakeWrapper::onVerify, this, closurePtr->m_dataCallback, dataPtr), 
                             boost::bind(&FakeWrapper::onVerifyError, this, closurePtr->m_verifyFailCallback, interestPtr));
    else
      m_executor->execute (boost::bind(closurePtr->m_unverifiedDataCallback, dataPtr));
  }

  void
  FakeWrapper::onVerify(const Closure::DataCallback & dataCallback, Ptr<Data> dataPtr)
  {
    m_executor->execute (boost::bind (dataCallback, dataPtr));
  }

  void
  FakeWrapper::onVerifyError(const Closure::VerifyFailCallback & failCallback, Ptr<Interest> interestPtr)
  {
    m_executor->execute (boost::bind (failCallback, interestPtr));
  }
}
