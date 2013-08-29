/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "simple-visitor.h"
#include "ndn.cxx/helpers/oid.h"

#include "../der-bool.h"
#include "../der-integer.h"
#include "../der-bit-string.h"
#include "../der-octet-string.h"
#include "../der-printable-string.h"
#include "../der-null.h"
#include "../der-sequence.h"
#include "../der-gtime.h"
#include "../der-oid.h"

using namespace std;

namespace ndn
{

namespace der
{
  boost::any 
  SimpleVisitor::visit (DerBool& derBool)
  {
    bool result = true;
    
    if(0 == derBool.getPayload()[0])
      result = false;
    
    return boost::any(result);
  }
  
  boost::any 
  SimpleVisitor::visit (DerInteger& derInteger)
  {
    return boost::any(derInteger.getPayload());
  }
  
  boost::any 
  SimpleVisitor::visit (DerPrintableString& derPStr)
  {
    return boost::any(string(derPStr.getPayload().buf(), derPStr.getPayload().size()));
  }
  
  boost::any 
  SimpleVisitor::visit (DerBitString& derBStr)
  {
    return boost::any(derBStr.getPayload());
  }

  boost::any 
  SimpleVisitor::visit (DerNull& derNull)
  {
    return boost::any();
  }
  
  boost::any 
  SimpleVisitor::visit (DerOctetString& derOStr)
  {
    return boost::any(derOStr.getPayload());
  }
  
  boost::any 
  SimpleVisitor::visit (DerOid& derOid)
  {
    vector<int> intList;
    int offset = 0;

    Blob & blob = derOid.getPayload();
      
    int first = blob[offset];
    
    intList.push_back(first / 40);
    intList.push_back(first % 40);

    offset++;
    
    while(offset < blob.size()){
      intList.push_back(derOid.decode128(offset));
    }
    
    return boost::any(OID(intList));
  }
  
  boost::any 
  SimpleVisitor::visit (DerSequence& derSeq)
  {
    return boost::any();
  }
  
  boost::any 
  SimpleVisitor::visit (DerGtime& derGtime)
  {
    string str(derGtime.getPayload().buf() , derGtime.getPayload().size());
    return boost::any(boost::posix_time::from_iso_string(str.substr(0, 8) + "T" + str.substr(8, 6)));
  }

}//der

}//ndn
