/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_NO_ARGU_DEPTH_FIRST_VISITOR_H_
#define _NDNB_PARSER_NO_ARGU_DEPTH_FIRST_VISITOR_H_

#include "no-argu-visitor.h"

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndnx-ndnb
 * \brief Depth-first visitor that takes no arguments and returns boost::any value
 */
class NoArguDepthFirstVisitor : public NoArguVisitor
{
public:
  virtual boost::any visit (Blob& );
  virtual boost::any visit (Udata&);
  virtual boost::any visit (Tag&  );
  virtual boost::any visit (Attr& );
  virtual boost::any visit (Dtag& );
  virtual boost::any visit (Dattr&);
  virtual boost::any visit (Ext&  );
};

} // NdnbParser
} // wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_NO_ARGU_DEPTH_FIRST_VISITOR_H_
