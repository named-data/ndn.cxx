/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <stdlib.h>
#include <sstream>

#include "oid.h"

#include "ndn.cxx/security/exception.h"
#include "ndn.cxx/helpers/der/der.h"


using namespace std;
using namespace ndn::security;

namespace ndn
{
  OID::OID(const vector<int> & oid)
    : m_oid(oid)
  {}

  OID::OID(const string & oid)
  {
    string str = oid + ".";

    size_t pos = 0;
    size_t ppos = 0;

    while(string::npos != pos){
      ppos = pos;

      pos = str.find_first_of('.', pos);
      if(string::npos == pos)
	break;

      m_oid.push_back(atoi(str.substr(ppos, pos - ppos).c_str()));

      pos++;
    }
  }
  
  OID::OID(const OID & oid)
    :m_oid(oid.m_oid)
  {}

  string OID::toString()
  {
    ostringstream convert;
    vector<int>::iterator it = m_oid.begin();
    for(; it < m_oid.end(); it++){
      if(it != m_oid.begin())
        convert << ".";
      convert << *it;
    }
    return convert.str();
  }

  bool OID::equal(const OID & oid)
  {
    vector<int>::const_iterator i = m_oid.begin();
    vector<int>::const_iterator j = oid.m_oid.begin();
    
    for (; i != m_oid.end () && j != oid.m_oid.end (); i++, j++)
    {
      if(*i != *j)
        return false;
    }

    if (i == m_oid.end () && j == oid.m_oid.end ())
      return true;
    else
      return false;
  }

  bool OID::operator == (const OID & oid)
  {
    return equal(oid);
  }

  bool OID::operator != (const OID & oid)
  {
    return !equal(oid);
  }
}//ndn
