/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "certificate-data-visitor.h"

#include "cert-extension-visitor.h"
#include "cert-validity-visitor.h"
#include "cert-subject-visitor.h"
#include "publickey-visitor.h"
#include "simple-visitor.h"

#include "../der.h"
#include "ndn.cxx/security/certificate/certificate-data.h"

#include "logging.h"

INIT_LOGGER("ndn.der.CertificateDataVisitor");

namespace ndn
{

namespace der
{
  void 
  CertificateDataVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    _LOG_DEBUG("CertificateDataVisitor::visit");

    const DerNodePtrList & children = derSeq.getChildren();
    CertValidityVisitor validityVisitor;
    children[0]->accept(validityVisitor, param);
    CertSubjectVisitor subjectVisitor;
    children[1]->accept(subjectVisitor, param);
    PublickeyVisitor pubkeyVisitor;
    security::CertificateData* certData = boost::any_cast<security::CertificateData*>(param);
    certData->setKey(*boost::any_cast<Ptr<security::Publickey> >(children[2]->accept(pubkeyVisitor)));
        
    if(children.size() > 3)
      {
        CertExtensionVisitor extnVisitor;
        children[3]->accept(extnVisitor, param);
      }
  }

}//der

}//ndn
