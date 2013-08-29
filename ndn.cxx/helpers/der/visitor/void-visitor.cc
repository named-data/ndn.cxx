/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "void-visitor.h"

namespace ndn
{

namespace der
{
  
  
  void 
  VoidVisitor::visit (DerBool& derBool, boost::any param)
  {}

  void
  VoidVisitor::visit (DerInteger& derBool, boost::any param)
  {}
  
  void 
  VoidVisitor::visit (DerPrintableString& derPStr, boost::any param)
  {}
  
  void 
  VoidVisitor::visit (DerBitString& derBStr, boost::any param)
  {}
  
  void
  VoidVisitor::visit (DerNull& derNull, boost::any param)
  {}

  void 
  VoidVisitor::visit (DerOctetString& derOStr, boost::any param)
  {}

  void
  VoidVisitor::visit (DerOid& derOid, boost::any param)
  {}
  
  void 
  VoidVisitor::visit (DerSequence& derSeq, boost::any param)
  {}
  
  void 
  VoidVisitor::visit (DerGtime& derGtime, boost::any param)
  {}

}//der

}//ndn
