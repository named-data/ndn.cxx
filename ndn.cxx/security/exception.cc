/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/exception.h"

using namespace std;

namespace ndn
{

namespace security
{
  SecException::SecException(const string & errMsg) throw()
    : m_errMsg(errMsg)
  {
  }

  SecException::~SecException() throw()
  {
  }
  
}//security

}//ndn
