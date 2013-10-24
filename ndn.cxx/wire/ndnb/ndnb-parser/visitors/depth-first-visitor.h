/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_DEPTH_FIRST_VISITOR_H_
#define _NDNB_PARSER_DEPTH_FIRST_VISITOR_H_

#include "visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Depth-first visitor that takes boot::any as argument and returns boost::any value
 */
class DepthFirstVisitor : public Visitor
{
public:
  virtual boost::any visit (Blob&,  boost::any);
  virtual boost::any visit (Udata&, boost::any);
  virtual boost::any visit (Tag&,   boost::any);
  virtual boost::any visit (Attr&,  boost::any);
  virtual boost::any visit (Dtag&,  boost::any);
  virtual boost::any visit (Dattr&, boost::any);
  virtual boost::any visit (Ext&,   boost::any);
};

} // NdnbParser
} // wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_DEPTH_FIRST_VISITOR_H_
