/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "cert-subject-visitor.h"

#include "cert-subject-descrypt-visitor.h"

#include "../der-sequence.h"

namespace ndn
{

namespace der
{
  void 
  CertSubjectVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    const DerNodePtrList & children = derSeq.getChildren();
    
    CertSubDescryptVisitor descryptVisitor;

    DerNodePtrList::const_iterator it = children.begin();

    while(it != children.end())
	(*it)->accept(descryptVisitor, param);
  }

}//der

}//ndn
