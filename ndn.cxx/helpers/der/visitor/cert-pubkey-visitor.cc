/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "cert-pubkey-visitor.h"

#include "simple-visitor.h"

#include "../der-sequence.h"

#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/security/certificate/publickey.h"

#include "logging.h"

INIT_LOGGER("ndn.der.CertPubkeyVisitor");

namespace ndn
{

namespace der
{
  void
  CertPubkeyVisitor::visit (DerSequence& derSeq, boost::any param)
  {
    // _LOG_DEBUG("CertPubkeyVisitor::visit");

    const DerNodePtrList & children = derSeq.getChildren();

    SimpleVisitor simpleVisitor;
    Ptr<DerSequence> algoSeq = DynamicCast<DerSequence>(children[0]); 
    OID algorithm = boost::any_cast<OID>(algoSeq->getChildren()[0]->accept (simpleVisitor));    
    security::Publickey pubkey(algorithm, *derSeq.getRaw());
 
    security::CertificateData* certData = boost::any_cast<security::CertificateData*> (param);

    certData->setKey(pubkey);
  }

}//der

}//ndn
