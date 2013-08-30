/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_DER_PUBLICKEY_VISITOR_H
#define NDN_DER_PUBLICKEY_VISITOR_H

#include "ndn.cxx/helpers/der/visitor/no-argu-visitor.h"

namespace ndn
{

namespace der
{
  class PublickeyVisitor : public NoArguVisitor
  {
  public:
    virtual boost::any visit (DerSequence&       );
  };
}//der

}//ndn

#endif
