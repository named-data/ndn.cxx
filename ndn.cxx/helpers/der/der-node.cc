/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-node.h"

#include "der-bool.h"
#include "der-integer.h"
#include "der-bit-string.h"
#include "der-octet-string.h"
#include "der-null.h"
#include "der-oid.h"
#include "der-sequence.h"
#include "der-printable-string.h"
#include "der-gtime.h"
#include "exception.h"

#include <iostream>



namespace ndn
{

namespace der
{
  DerNode::DerNode()
    :m_parent(NULL)
  {}

  DerNode::DerNode(DerType type)
    :m_type(type),
     m_parent(NULL)
  {}

  DerNode::DerNode(InputIterator &start)
    :m_parent(NULL)
  {
    decode(start);
  }
  
  DerNode::~DerNode ()
  {}

  void
  DerNode::encodeHeader(int size)
  {
    m_header.push_back((char)m_type);

    if(size >= 127)
      {
        int val = size;
        char buf[sizeof(val) + 1];
        char *p = &(buf[sizeof(buf)-1]);
        int n = 0;
        int mask = 1 << 8 - 1;

        while(val != 0)
          {
            p[0] = (char)(val & mask);
            p--;
            n++;
            val >>= 8;
          }

        p[0] = (char)(1<<7 | n);
        n++;

        m_header.insert(m_header.end(), p, p+n);
      }
    else if(size >= 0)
      {
        m_header.push_back((char)size);
      }
    else
      throw NegativeLengthException("Negative length");
  }

  int
  DerNode::decodeHeader(InputIterator & start)
  {
    uint8_t type = start.ReadU8();
    m_header.push_back(type);
    m_type = static_cast<DerType>((int)type);

    uint8_t sizeLen = start.ReadU8();    
    m_header.push_back(sizeLen);

    bool shortFormat = sizeLen & (1 << 7);

    if(shortFormat)
      {        
        return sizeLen;
      }
    else
      {
        uint8_t byte;
        int size = 0;
        do
          {
            byte = start.ReadU8();
            m_header.push_back(byte);
            size = size * 128 + (byte & (1<<7 - 1));
          }
        while(byte & (1 << 7));

        return size;
      }
  }

  void
  DerNode::encode (OutputIterator & start)
  {
    start.write(m_header.buf(), m_header.size());
    start.write(m_payload.buf(), m_payload.size());
  }

  void 
  DerNode::decode (InputIterator & start)
  {
    int payloadSize = decodeHeader(start);
    if(payloadSize > 0 )
      {
        char buf[payloadSize];
        start.read(buf, payloadSize);
        m_payload.insert(m_payload.end(), buf, buf + payloadSize);
      }
  }


  Ptr<DerNode>
  DerNode::parseDer(InputIterator &start)
  {
    uint8_t type = start.PeekU8();

    switch(type)
      {
      case DER_BOOLEAN:
        return Ptr<DerBool> (new DerBool(start));
      case DER_INTEGER:
        return Ptr<DerInteger> (new DerInteger(start));
      case DER_BIT_STRING:
        return Ptr<DerBitString> (new DerBitString(start));
      case DER_OCTET_STRING:
        return Ptr<DerOctetString> (new DerOctetString(start));
      case DER_NULL:
        return Ptr<DerNull> (new DerNull(start));
      case DER_OBJECT_IDENTIFIER:
        return Ptr<DerOid> (new DerOid(start));
      case DER_SEQUENCE:
        return Ptr<DerSequence> (new DerSequence(start));
      case DER_PRINTABLE_STRING:
        return Ptr<DerPrintableString> (new DerPrintableString(start));
      case DER_GENERALIZED_TIME:
        return Ptr<DerGtime> (new DerGtime(start));
      default:
        throw DerDecodingException("Unimplemented DER types");
      }
  }

}//der

}//ndn
