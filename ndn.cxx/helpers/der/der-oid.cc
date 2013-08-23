/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-oid.h"

#include "exception.h"

#include <stdlib.h>

namespace ndn
{

namespace der
{
  DerOid::DerOid(const OID & oid)
    :DerNode(DER_OBJECT_IDENTIFIER)
  {
    prepareEncoding(oid.getIntegerList());
  }
  

  DerOid::DerOid(const string & oidStr)
    :DerNode(DER_OBJECT_IDENTIFIER)
  {
    vector<int> value;

    string str = oidStr + ".";

    size_t pos = 0;
    size_t ppos = 0;

    while(string::npos != pos){
      ppos = pos;

      pos = str.find_first_of('.', pos);
      if(string::npos == pos)
	break;

      value.push_back(atoi(str.substr(ppos, pos - ppos).c_str()));

      pos++;
    }

    prepareEncoding(value);
  }

  DerOid::DerOid(const vector<int> & value)
    :DerNode(DER_OBJECT_IDENTIFIER)
  {
    prepareEncoding(value);
  }

  DerOid::DerOid(InputIterator &start)
    :DerNode(start)
  {}
    
  DerOid::~DerOid()
  {}

  void
  DerOid::prepareEncoding(const vector<int> & value)
  {
    ostringstream os;

    int firstNumber = 0;
    
    if(value.size() >= 1){
      if(0 <= value[0] && 2 >= value[0])
	firstNumber = value[0] * 40;
      else
	throw DerEncodingException("first integer of oid is out of range");
    }
    else
      throw DerEncodingException("no integer in oid");

    if(value.size() >= 2){
      if(0 <= value[1] && 39 >= value[1])
	firstNumber += value[1];
      else
	throw DerEncodingException("second integer of oid is out of range");
    }

    encode128(firstNumber, os);

    if(value.size() > 2){
      int i = 2;
      for(; i < value.size(); i++)
	encode128(value[i], os);
    }

    DerNode::encodeHeader(os.str().size());
    m_payload.insert(m_payload.end(), os.str().begin(), os.str().end());
  }
    
  void
  DerOid::encode128(int value, ostringstream & os)
  {
    int mask = 1 << 7 - 1;

    if(128 > value)
      {
	uint8_t singleByte = (uint8_t) mask & value;
	os.write((char *)&singleByte, 1);
      }
    else{
      uint8_t buf[(sizeof(value)*8 + 6)/7 + 1];
      uint8_t *p = &(buf[sizeof(buf)-1]);
      int n = 1;

      p[0] = (uint8_t)(value & mask);
      value >>= 7;

      while(value != 0)
	{
	  (--p)[0] = (uint8_t)((value & mask) | (1 << 7));
	  n++;
	  value >>= 7;
	}
      
      os.write((char *)p, n);
    }
  }

}//der

}//ndn
