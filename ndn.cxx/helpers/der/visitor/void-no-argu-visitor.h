/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_VOID_NO_ARGU_ABSTRACT_VISITOR_H
#define NDN_DER_VOID_NO_ARGU_ABSTRACT_VISITOR_H

#include "../common.h"

namespace ndn
{

namespace der
{
  class VoidNoArguVisitor
  {
  public:
    virtual void visit (DerBool&           )=0;
    virtual void visit (DerInteger&        )=0;
    virtual void visit (DerPrintableString&)=0;
    virtual void visit (DerBitString&      )=0;
    virtual void visit (DerNull&           )=0;
    virtual void visit (DerOctetString&    )=0;
    virtual void visit (DerOid&            )=0;
    virtual void visit (DerSequence&       )=0;
    virtual void visit (DerGtime&          )=0;
  };

}//der

}//ndn

#endif
