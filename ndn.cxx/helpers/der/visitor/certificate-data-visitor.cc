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

#include "simple-visitor.h"
#include "publickey-visitor.h"
#include "../der.h"

#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/security/certificate/certificate-subdescrpt.h"
#include "ndn.cxx/security/certificate/certificate-extension.h"


#include "logging.h"

INIT_LOGGER("ndn.der.CertificateDataVisitor");

namespace ndn
{

namespace der
{
  /*
   * CertificateDataVisitor
   */
  void 
  CertificateDataVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    // _LOG_DEBUG("CertificateDataVisitor::visit");

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

  /*
   * CertValidityVisitor
   */
  void 
  CertValidityVisitor::visit (DerSequence& derSeq, boost::any param)
  {
    // _LOG_DEBUG("CertValidityVisitor::visit");
    
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

  /*
   * CertSubDescryptVisitor
   */
  void
  CertSubDescryptVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    security::CertificateData* certData = boost::any_cast<security::CertificateData*> (param); 
    
    const DerNodePtrList & children = derSeq.getChildren();
    
    SimpleVisitor simpleVisitor;

    OID oid = boost::any_cast<OID>(children[0]->accept(simpleVisitor));
    string value = boost::any_cast<string>(children[1]->accept(simpleVisitor));

    security::CertificateSubDescrypt subDescrypt(oid, value);

    certData->addSubjectDescription(subDescrypt);
  }

  /*
   * CertSubjectVisitor
   */
  void 
  CertSubjectVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    // _LOG_DEBUG("CertSubjectVisitor::visit");

    const DerNodePtrList & children = derSeq.getChildren();
    
    CertSubDescryptVisitor descryptVisitor;

    DerNodePtrList::const_iterator it = children.begin();

    while(it != children.end())
      {
	(*it)->accept(descryptVisitor, param);
        it++;
      }
  }

  /*
   * CertExtnEntryVisitor
   */
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

  /*
   * CertExtensionVisitor
   */
  void 
  CertExtensionVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    const DerNodePtrList & children = derSeq.getChildren();
    
    CertExtnEntryVisitor extnEntryVisitor;

    DerNodePtrList::const_iterator it = children.begin();

    while(it != children.end())
      {
	(*it)->accept(extnEntryVisitor, param);
        it++;
      }
  }


}//der

}//ndn
