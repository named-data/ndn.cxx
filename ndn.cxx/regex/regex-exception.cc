/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-exception.h"

using namespace std;

namespace ndn
{

namespace regex
{
  RegexException::RegexException(const string & sStr) throw()
    : m_msg(sStr)
  {
  }

  RegexException::~RegexException() throw()
  {
  }

  string RegexException::getMsg()
  { 
    return m_msg;
  }

}//regex

}//ndn
