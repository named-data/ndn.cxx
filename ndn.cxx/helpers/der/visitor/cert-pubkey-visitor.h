/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_CERT_PUBKEY_VISITOR_H
#define NDN_CERT_PUBKEY_VISITOR_H

#include "void-visitor.h"

namespace ndn
{

namespace der
{

  class CertPubkeyVisitor : public VoidVisitor
  {
  public:
    virtual void visit (DerSequence&,         boost::any);
  };

}//der

}//ndn

#endif
