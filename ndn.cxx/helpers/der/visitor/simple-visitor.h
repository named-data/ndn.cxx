/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_DER_SIMPLE_VISITOR_H
#define NDN_DER_SIMPLE_VISITOR_H

#include "no-argu-visitor.h"


namespace ndn
{

namespace der
{
  
  class SimpleVisitor : public NoArguVisitor
  {
  public:
    virtual boost::any visit (DerBool&           );
    virtual boost::any visit (DerInteger&        );
    virtual boost::any visit (DerPrintableString&);
    virtual boost::any visit (DerBitString&      );
    virtual boost::any visit (DerNull&           );
    virtual boost::any visit (DerOctetString&    );
    virtual boost::any visit (DerOid&            );
    virtual boost::any visit (DerSequence&       );
    virtual boost::any visit (DerGtime&          );
  };

}//der

}//ndn
 

#endif
