/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef _NDNB_PARSER_VOID_VISITOR_H_
#define _NDNB_PARSER_VOID_VISITOR_H_

#include "../common.h"
#include <boost/any.hpp>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

/**
 * \ingroup ndn-ndnb
 * \brief Visitor interface that takes one boost::any argument and returns nothing
 *
 * \see http://www.ndnx.org/releases/latest/doc/technical/BinaryEncoding.html
 * for ndnb encoding format help
 */
class VoidVisitor
{
public:
  virtual void visit (Blob&,  boost::any)=0; ///< \brief Method accepting BLOB block  
  virtual void visit (Udata&, boost::any)=0; ///< \brief Method accepting UDATA block 
  virtual void visit (Tag&,   boost::any)=0; ///< \brief Method accepting TAG block   
  virtual void visit (Attr&,  boost::any)=0; ///< \brief Method accepting ATTR block  
  virtual void visit (Dtag&,  boost::any)=0; ///< \brief Method accepting DTAG block  
  virtual void visit (Dattr&, boost::any)=0; ///< \brief Method accepting DATTR block 
  virtual void visit (Ext&,   boost::any)=0; ///< \brief Method accepting EXT block

  virtual ~VoidVisitor () { }
};

} // NdnbParser
} // wire

NDN_NAMESPACE_END

#endif // _NDNB_PARSER_VOID_VISITOR_H_
