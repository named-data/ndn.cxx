/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_VOID_NO_ARGU_DEPTH_FIRST_VISITOR_H_
#define _NDNB_PARSER_VOID_NO_ARGU_DEPTH_FIRST_VISITOR_H_

#include "void-no-argu-visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Depth-first visitor that takes no arguments and returns nothing
 */
class VoidNoArguDepthFirstVisitor : public VoidNoArguVisitor
{
public:
  virtual void visit (Blob& );
  virtual void visit (Udata&);
  virtual void visit (Tag&  );
  virtual void visit (Attr& );
  virtual void visit (Dtag& );
  virtual void visit (Dattr&);
  virtual void visit (Ext&  );
};

} // NdnbParser
} // wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_VOID_NO_ARGU_DEPTH_FIRST_VISITOR_H_
