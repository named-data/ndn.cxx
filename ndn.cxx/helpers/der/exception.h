/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_DER_EXCEPTION_H
#define NDN_DER_EXCEPTION_H

#include <exception>
#include <string>

using namespace std;

namespace ndn
{

namespace der
{

  class DerException : public exception
  {
  public:
    DerException(const string & errMsg) throw();
    
    ~DerException() throw();
    
    inline string Msg() {return m_errMsg;}
    
  private:
    const string m_errMsg;
  };


  class NegativeLengthException : public DerException
  {
  public:
    NegativeLengthException(const string & errMsg)
    :DerException(errMsg)
    {}
  };

  class DerEncodingException : public DerException
  {
  public:
    DerEncodingException(const string & errMsg)
    :DerException(errMsg)
    {}
  };

  class DerDecodingException : public DerException
  {
  public:
    DerDecodingException(const string & errMsg)
    :DerException(errMsg)
    {}
  };

} //der

} //ndn

#endif
