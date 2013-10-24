/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "void-depth-first-visitor.h"

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

void
VoidDepthFirstVisitor::visit (Blob &n, boost::any param)
{
  // Buffer n.m_blob;
}
 
void
VoidDepthFirstVisitor::visit (Udata &n, boost::any param)
{
  // std::string n.m_udata;
}
 
void
VoidDepthFirstVisitor::visit (Tag &n, boost::any param)
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
}
 
void
VoidDepthFirstVisitor::visit (Dtag &n, boost::any param)
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
}
 
void
VoidDepthFirstVisitor::visit (Attr &n, boost::any param)
{
  // std::string n.m_attr;
  // Ptr<Udata> n.m_value;
}
 
void
VoidDepthFirstVisitor::visit (Dattr &n, boost::any param)
{
  // uint32_t n.m_dattr;
  // Ptr<Udata> n.m_value;
}
 
void
VoidDepthFirstVisitor::visit (Ext &n, boost::any param)
{
  // uint64_t n.m_extSubtype;
}

} // NdnbParser
} // wire

NDN_NAMESPACE_END
