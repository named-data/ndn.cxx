/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_NAME_COMPONENTS_VISITOR_H_
#define _NDNB_PARSER_NAME_COMPONENTS_VISITOR_H_

#include "void-depth-first-visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Visitor to obtain fill NdnxName object with name components
 */
class NameVisitor : public VoidDepthFirstVisitor
{
public:
  virtual void visit (Dtag &n, boost::any param/*should be Name* */);
};

} // NdnbParser
} // wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_NAME_COMPONENTS_VISITOR_H_

