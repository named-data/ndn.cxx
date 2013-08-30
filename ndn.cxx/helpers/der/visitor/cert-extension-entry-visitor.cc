/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "cert-extension-entry-visitor.h"

#include "simple-visitor.h"

#include "../der-sequence.h"

#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/security/certificate/certificate-extension.h"

namespace ndn
{

namespace der
{
  void 
  CertExtnEntryVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    security::CertificateData* certData = boost::any_cast<security::CertificateData*> (param); 
    
    const DerNodePtrList & children = derSeq.getChildren();
    
    SimpleVisitor simpleVisitor;

    OID oid = boost::any_cast<OID>(children[0]->accept(simpleVisitor));
    bool critical = boost::any_cast<bool>(children[1]->accept(simpleVisitor));
    const Blob & value = boost::any_cast<const Blob &>(children[2]->accept(simpleVisitor));

    security::CertificateExtension extension(oid, critical, value);

    certData->addExtension(extension);
  }

}//der

}//ndn
