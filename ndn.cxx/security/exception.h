/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_SECURITY_EXCEPTION_H
#define NDN_SECURITY_EXCEPTION_H

#include <exception>
#include <string>

using namespace std;

namespace ndn
{

namespace security
{

  class SecException : public exception
  {
  public:
    SecException(const string & errMsg) throw();
    
    ~SecException() throw();
    
    inline string Msg() {return m_errMsg;}
    
  private:
    const string m_errMsg;
  };

  class UnrecognizedKeyFormatException : public SecException
  {
  public:
    UnrecognizedKeyFormatException(const string & errMsg)
    :SecException(errMsg)
    {}
  };

  class UnrecognizedDigestAlgoException : public SecException
  {
  public:
    UnrecognizedDigestAlgoException(const string & errMsg)
    :SecException(errMsg)
    {}
  };
} //security

} //ndn

#endif
