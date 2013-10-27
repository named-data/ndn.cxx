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

namespace ndn {
namespace security {


class SecException : public std::exception
{
public:
  SecException(const std::string & errMsg) throw()
  : m_errMsg(errMsg)
  {
  }
  ~SecException() throw()
  {
  }

  const char* what() const throw()
  {
    return m_errMsg.c_str();
  }
    
private:
  const std::string m_errMsg;
};

class UnrecognizedKeyFormatException : public SecException
{
public:
  UnrecognizedKeyFormatException(const std::string & errMsg)
    :SecException(errMsg)
  {}
};

class UnrecognizedDigestAlgoException : public SecException
{
public:
  UnrecognizedDigestAlgoException(const std::string & errMsg)
    :SecException(errMsg)
  {}
};


} //security
} //ndn

#endif // NDN_SECURITY_EXCEPTION_H
