/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_PRINT_VISITOR
#define NDN_DER_PRINT_VISITOR

#include "void-visitor.h"

#include "ndn.cxx/fields/blob.h"

#include <string>

using namespace std;

namespace ndn
{

namespace der
{

  class PrintVisitor : public VoidVisitor
  {
  public:
    virtual void visit (DerBool&,             boost::any);
    virtual void visit (DerInteger&,          boost::any);
    virtual void visit (DerPrintableString&,  boost::any);
    virtual void visit (DerBitString&,        boost::any);
    virtual void visit (DerNull&,             boost::any);
    virtual void visit (DerOctetString&,      boost::any);
    virtual void visit (DerOid&,              boost::any);
    virtual void visit (DerSequence&,         boost::any);
    virtual void visit (DerGtime&,            boost::any);

  private:
    static void printData(const Blob & blob, const string & indent, int offset = 0);
  };

}//der

}//ndn

#endif
