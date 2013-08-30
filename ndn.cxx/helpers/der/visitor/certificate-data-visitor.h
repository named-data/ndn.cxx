/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_DER_CERTIFICATE_DATA_VISITOR_H
#define NDN_DER_CERTIFICATE_DATA_VISITOR_H

#include "void-visitor.h"

namespace ndn
{

namespace der
{
  class CertificateDataVisitor : public VoidVisitor
  {
    virtual void visit (DerSequence&,         boost::any);
  };

  class CertValidityVisitor : public VoidVisitor
  {
  public:
    virtual void visit (DerSequence&,         boost::any);
  };

  class CertSubDescryptVisitor : public VoidVisitor
  {
  public:
    virtual void visit (DerSequence&,         boost::any);
  };

  class CertSubjectVisitor : public VoidVisitor
  {
    virtual void visit (DerSequence&,         boost::any);
  };

  class CertExtnEntryVisitor : public VoidVisitor
  {
    virtual void visit (DerSequence&,         boost::any);
  };
  
  class CertExtensionVisitor : public VoidVisitor
  {
    virtual void visit (DerSequence&,         boost::any);
  };

}//der

}//ndn

#endif
