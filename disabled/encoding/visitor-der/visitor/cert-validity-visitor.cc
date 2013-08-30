/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "cert-validity-visitor.h"

#include "simple-visitor.h"
#include "../der.h"

#include "ndn.cxx/security/certificate/certificate-data.h"

#include "logging.h"

INIT_LOGGER("ndn.der.CertValidityVisitor");

namespace ndn
{

namespace der
{
  void 
  CertValidityVisitor::visit (DerSequence& derSeq, boost::any param)
  {
    _LOG_DEBUG("CertValidityVisitor::visit");
    
    security::CertificateData* certData = boost::any_cast<security::CertificateData*> (param); 

    const DerNodePtrList & children = derSeq.getChildren();
    
    SimpleVisitor simpleVisitor;

    Time notBefore = boost::any_cast<Time>(children[0]->accept(simpleVisitor));
    Time notAfter = boost::any_cast<Time>(children[1]->accept(simpleVisitor));

    // _LOG_DEBUG("parsed notBefore: " << notBefore);
    // _LOG_DEBUG("parsed notAfter: " << notAfter);

    certData->setNotBefore(notBefore);
    certData->setNotAfter(notAfter);
  }

}//der

}//ndn
