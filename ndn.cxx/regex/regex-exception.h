/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_EXCEPTION_H
#define NDN_REGEX_EXCEPTION_H

#include <exception>
#include <string>

using namespace std;

namespace ndn
{

namespace regex
{

  class RegexException : public exception {
  public:
    RegexException(const string sStr) throw();
    
    virtual ~RegexException() throw();
    
    string getMsg();

  private:
    const string m_msg;
  };

}//regex

}//ndn

#endif
