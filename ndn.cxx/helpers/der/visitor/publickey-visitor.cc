/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "publickey-visitor.h"
#include "simple-visitor.h"

#include "ndn.cxx/security/certificate/publickey.h"

namespace ndn
{

namespace der
{
  boost::any 
  PublickeyVisitor::visit (DerSequence& derSeq)
  {
    const DerNodePtrList & children = derSeq.getChildren();

    SimpleVisitor simpleVisitor;
    Ptr<DerSequence> algoSeq = DynamicCast<DerSequence>(children[0]); 
    OID algorithm = boost::any_cast<OID>(algoSeq->getChildren()[0]->accept (simpleVisitor));  
    Ptr<Blob> raw = derSeq.getRaw();   
    return boost::any(Ptr<security::Publickey>(new security::Publickey(algorithm, *raw)));    
  }

}//der

}//ndn
