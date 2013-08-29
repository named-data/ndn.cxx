/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "cert-extension-visitor.h"

#include "cert-extension-entry-visitor.h"

#include "../der-sequence.h"

namespace ndn
{

namespace der
{
  void 
  CertExtensionVisitor::visit(DerSequence& derSeq, boost::any param)
  {
    const DerNodePtrList & children = derSeq.getChildren();
    
    CertExtnEntryVisitor extnEntryVisitor;

    DerNodePtrList::const_iterator it = children.begin();

    while(it != children.end())
	(*it)->accept(extnEntryVisitor, param);
  }

}//der

}//ndn
