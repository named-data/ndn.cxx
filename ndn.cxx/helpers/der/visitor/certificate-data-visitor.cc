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
#include "cert-

#include "../der-sequence.h"

namespace ndn
{

namespace der
{
  void 
  CertSubjectVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    const DerNodePtrList & children = derSeq.getChildren();
    children[0]->accept(CertValidityVisitor());
    children[1]->accept(CertSubDescryptVisitor());
    children[2]->accept(

    DerNodePtrList::const_iterator it = children.begin();
    
  }

}//der

}//ndn
