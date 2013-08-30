/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/helpers/der/visitor/no-argu-visitor.h"

namespace ndn
{

namespace der
{
  boost::any
  NoArguVisitor::visit (DerBool& derbool)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerInteger& derInteger)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerPrintableString& derPStr)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerBitString& derBStr)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerNull& derNull)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerOctetString& derOStr)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerOid& derOid)
  {return  boost::any(0);}

  boost::any 
  NoArguVisitor::visit (DerSequence& derSeq)
  {return  boost::any(0);}
  
  boost::any 
  NoArguVisitor::visit (DerGtime& derGtime)
  {return  boost::any(0);}
  
}//der

}//ndn
