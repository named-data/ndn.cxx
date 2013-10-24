/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_VOID_DEPTH_FIRST_VISITOR_H_
#define _NDNB_PARSER_VOID_DEPTH_FIRST_VISITOR_H_

#include "void-visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Depth-first visitor that takes one argument and returns nothing
 */
class VoidDepthFirstVisitor : public VoidVisitor
{
public:
  virtual void visit (Blob&,  boost::any);
  virtual void visit (Udata&, boost::any);
  virtual void visit (Tag&,   boost::any);
  virtual void visit (Attr&,  boost::any);
  virtual void visit (Dtag&,  boost::any);
  virtual void visit (Dattr&, boost::any);
  virtual void visit (Ext&,   boost::any);
};

} // NdnbParser
} // wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_VOID_DEPTH_FIRST_VISITOR_H_
