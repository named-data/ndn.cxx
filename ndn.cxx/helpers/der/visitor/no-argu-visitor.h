/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_NO_ARGU_ABSTRACT_VISITOR_H
#define NDN_DER_NO_ARGU_ABSTRACT_VISITOR_H

#include "../common.h"
#include <boost/any.hpp>

namespace ndn
{

namespace der
{
  class NoArguVisitor
  {
  public:
    virtual boost::any visit (DerBool&           )=0;
    virtual boost::any visit (DerInteger&        )=0;
    virtual boost::any visit (DerPrintableString&)=0;
    virtual boost::any visit (DerBitString&      )=0;
    virtual boost::any visit (DerNull&           )=0;
    virtual boost::any visit (DerOctetString&    )=0;
    virtual boost::any visit (DerOid&            )=0;
    virtual boost::any visit (DerSequence&       )=0;
    virtual boost::any visit (DerGtime&          )=0;
  };

}//der

}//ndn

#endif
