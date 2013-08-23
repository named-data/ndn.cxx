/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_VOID_ABSTRACT_VISITOR_H
#define NDN_DER_VOID_ABSTRACT_VISITOR_H

#include "../common.h"
#include <boost/any.hpp>

namespace ndn
{

namespace der
{
  class VoidVisitor
  {
  public:
    virtual void visit (DerBool&,             boost::any)=0;
    virtual void visit (DerInteger&,          boost::any)=0;
    virtual void visit (DerPrintableString&,  boost::any)=0;
    virtual void visit (DerBitString&,        boost::any)=0;
    virtual void visit (DerNull&,             boost::any)=0;
    virtual void visit (DerOctetString&,      boost::any)=0;
    virtual void visit (DerOid&,              boost::any)=0;
    virtual void visit (DerSequence&,         boost::any)=0;
    virtual void visit (DerGtime&,            boost::any)=0;
  };

}//der

}//ndn

#endif
