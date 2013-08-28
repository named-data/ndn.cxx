/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "name-visitor.h"

#include "string-visitor.h"
#include "../syntax-tree/dtag.h"

#include "ndn.cxx/fields/name.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace CcnbParser {

void
NameVisitor::visit (Dtag &n, boost::any param/*should be Name* */)
{
  // uint32_t n.m_dtag;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  static StringVisitor stringVisitor; 
 
  Name &components = *(boost::any_cast<Name*> (param));

  switch (n.m_dtag)
    {
    case NDN_DTAG_Component:
      if (n.m_nestedTags.size()!=1) // should be exactly one UDATA inside this tag
        throw CcnbDecodingException ();
      components.append (
                      boost::any_cast<std::string> ((*n.m_nestedTags.begin())->accept(
                                                                                      stringVisitor
                                                                                      )));
      break;
    default:
      VoidDepthFirstVisitor::visit (n, param);
      break;
    }
}

} // CcnbParser
} // wire

NDN_NAMESPACE_END
