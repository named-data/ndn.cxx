/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_ABSTRACT_VISITOR_H
#define NDN_DER_ABSTRACT_VISITOR_H

#include "../common.h"
#include <boost/any.hpp>

namespace ndn
{

namespace der
{
  class Visitor
  {
  public:
    virtual boost::any visit (DerBool&,             boost::any)=0;
    virtual boost::any visit (DerInteger&,          boost::any)=0;
    virtual boost::any visit (DerPrintableString&,  boost::any)=0;
    virtual boost::any visit (DerBitString&,        boost::any)=0;
    virtual boost::any visit (DerNull&,             boost::any)=0;
    virtual boost::any visit (DerOctetString&,      boost::any)=0;
    virtual boost::any visit (DerOid&,              boost::any)=0;
    virtual boost::any visit (DerSequence&,         boost::any)=0;
    virtual boost::any visit (DerGtime&,            boost::any)=0;
  };

}//der

}//ndn

#endif
