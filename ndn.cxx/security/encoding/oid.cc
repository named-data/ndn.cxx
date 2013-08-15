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

#include "ndn.cxx/security/exception.h"

#include "der.h"
#include "oid.h"

using namespace std;

namespace ndn
{

namespace security
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

  OID::OID(const Blob & blob)
  {
    if(0x06 != blob[0])
      throw SecException("decode Object Identifier, Type mismatch");

    DERendec endec;

    int offset = 1;

    int size = endec.decodeSize(blob, offset);
    int end = offset + size;

    int first = blob[offset];
    
    m_oid.push_back(first / 40);
    m_oid.push_back(first % 40);

    offset++;
    
    while(offset < end){
      m_oid.push_back(endec.decodeInteger128(blob, offset));
    }
  }

  Ptr<Blob> OID::toDER()
  {
    DERendec endec;
    Ptr<Blob> result = Ptr<Blob>::Create();

    result->push_back(0x06);

    int data = 0;
    
    if(m_oid.size() >= 1){
      if(0 <= m_oid[0] && 2 >= m_oid[0])
	data = m_oid[0] * 40;
      else
	throw SecException("first integer of oid is out of range");
    }
    else
      throw SecException("no integer in oid");

    if(m_oid.size() >= 2){
      if(0 <= m_oid[1] && 39 >= m_oid[1])
	data += m_oid[1];
      else
	throw SecException("second integer of oid is out of range");
    }

    Ptr<Blob> tmpResult = Ptr<Blob>::Create();

    Ptr<Blob> dataPtr = endec.encodeInteger128(data);

    tmpResult->insert(tmpResult->end(), dataPtr->begin(), dataPtr->end());

    if(m_oid.size() > 2){
      int i = 2;
      for(; i < m_oid.size(); i++){
	dataPtr = endec.encodeInteger128(m_oid[i]);
	tmpResult->insert(tmpResult->end(), dataPtr->begin(), dataPtr->end());
      }
    }

    Ptr<Blob> lenPtr = endec.encodeSize(tmpResult->size());

    result->insert(result->end(), lenPtr->begin(), lenPtr->end());
    result->insert(result->end(), tmpResult->begin(), tmpResult->end());
    
    return result;
  }

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

}//security

}//ndn
