/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "depth-first-visitor.h"

#include "../syntax-tree/blob.h"
#include "../syntax-tree/udata.h"
#include "../syntax-tree/tag.h"
#include "../syntax-tree/dtag.h"
#include "../syntax-tree/attr.h"
#include "../syntax-tree/dattr.h"
#include "../syntax-tree/ext.h"

#include <boost/foreach.hpp>

NDN_NAMESPACE_BEGIN

namespace wire {
namespace NdnbParser {

boost::any
DepthFirstVisitor::visit (Blob &n, boost::any param)
{
  // Buffer n.m_blob;
  return n.m_blob;
}
 
boost::any
DepthFirstVisitor::visit (Udata &n, boost::any param)
{
  // std::string n.m_udata;
  return n.m_udata;
}
 
boost::any
DepthFirstVisitor::visit (Tag &n, boost::any param)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_attrs;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this, param);
    }
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this, param);
    }
  return boost::any();
}

boost::any
DepthFirstVisitor::visit (Dtag &n, boost::any param)
{
  // std::string n.m_tag;
  // std::list<Ptr<Block> > n.m_attrs;
  // std::list<Ptr<Block> > n.m_nestedBlocks;
  BOOST_FOREACH (Ptr<Block> block, n.m_attrs)
    {
      block->accept (*this, param);
    }
  BOOST_FOREACH (Ptr<Block> block, n.m_nestedTags)
    {
      block->accept (*this, param);
    }
  return boost::any ();
}

boost::any
DepthFirstVisitor::visit (Attr &n, boost::any param)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
  return boost::any ();
}

boost::any
DepthFirstVisitor::visit (Dattr &n, boost::any param)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
  return boost::any ();
}
 
boost::any
DepthFirstVisitor::visit (Ext &n, boost::any param)
{
  // uint64_t n.m_extSubtype;
  return n.m_extSubtype;
}

} // NdnbParser
} // wire

NDN_NAMESPACE_END
