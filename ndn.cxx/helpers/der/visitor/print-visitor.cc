/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "print-visitor.h"

#include "../der-bool.h"
#include "../der-integer.h"
#include "../der-bit-string.h"
#include "../der-octet-string.h"
#include "../der-printable-string.h"
#include "../der-null.h"
#include "../der-sequence.h"
#include "../der-gtime.h"
#include "../der-oid.h"

#include <iostream>

namespace ndn
{

namespace der
{
  
  void 
  PrintVisitor::visit (DerBool& derBool, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
        
    printData(derBool.getHeader(), indent);
    printData(derBool.getPayload(), indent + "   ");
  }

  void
  PrintVisitor::visit (DerInteger& derInteger, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
        
    printData(derInteger.getHeader(), indent);
    printData(derInteger.getPayload(), indent + "   ");
  }
    
  void
  PrintVisitor::visit (DerPrintableString& derPStr, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
        
    printData(derPStr.getHeader(), indent);
    printData(derPStr.getPayload(), indent + "   ");
  }

  void 
  PrintVisitor::visit (DerBitString& derBStr, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
        
    printData(derBStr.getHeader(), indent);
    const Blob & payload = derBStr.getPayload();
    cout << indent << "   " << " " << hex << setw(2) << setfill('0') << (int)(uint8_t)payload[0] << endl;
    printData(payload, indent + "   ", 1);
  }

  void 
  PrintVisitor::visit (DerNull& derNull, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
        
    printData(derNull.getHeader(), indent);
    printData(derNull.getPayload(), indent + "   ");

  }

  void 
  PrintVisitor::visit (DerOctetString& derOStr, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
        
    printData(derOStr.getHeader(), indent);
    printData(derOStr.getPayload(), indent + "   ");
  }
  
  void 
  PrintVisitor::visit (DerOid& derOid, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
	
    printData(derOid.getHeader(), indent);
    printData(derOid.getPayload(), indent + "   ");

  }

  void 
  PrintVisitor::visit (DerGtime& derGtime, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
	
    printData(derGtime.getHeader(), indent);
    printData(derGtime.getPayload(), indent + "   ");
  }

  void 
  PrintVisitor::visit (DerSequence& derSequence, boost::any param)
  {
    const string & indent = boost::any_cast<const string &>(param);
    
    printData(derSequence.getHeader(), indent);

    const DerNodePtrList & children = derSequence.getChildren();
    DerNodePtrList::const_iterator it = children.begin();
    for(; it != children.end(); it++)
	(*it)->accept(*this, indent + " | ");
  }


  void 
  PrintVisitor::printData(const Blob & blob, const string & indent, int offset)
  {
    cout << indent;

    int count = 0;
    for(int i = offset; i < blob.size(); i++)
      {
        cout << " " << hex << setw(2) << setfill('0') << (int)(uint8_t)blob[i];
        count++;
        if(8 == count)
          {
            count = 0;
            cout << "\n" << indent;
          }
      }
    cout << endl;

  }


}//der

}//ndn
