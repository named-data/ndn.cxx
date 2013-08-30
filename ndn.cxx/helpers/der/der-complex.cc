/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#include "der-complex.h"

#include "logging.h"

INIT_LOGGER("ndn.der.DerComplex")

namespace ndn
{

namespace der
{
  DerComplex::DerComplex ()
    :DerNode(),
     m_childChanged(false),
     m_size(0)
  {}
  
  DerComplex::DerComplex (DerType type)
    :DerNode(type),
     m_childChanged(false),
     m_size(0)
  {}

  DerComplex::DerComplex (InputIterator & start)
    :DerNode(),
     m_childChanged(false),
     m_size(0)
  {
    m_size = DerNode::decodeHeader(start);
    // _LOG_DEBUG("Size: " << m_size);
    
    int accSize = 0;
    
    while(accSize < m_size)
      {
        // _LOG_DEBUG("accSize: " << accSize);
        Ptr<DerNode> nodePtr = DerNode::parse(start);
        accSize += nodePtr->getSize();
        addChild(nodePtr, false);
      }
  }

  DerComplex::~DerComplex()
  {}

  int
  DerComplex::getSize ()
  {
    if(m_childChanged)
      {
	updateSize();
	m_childChanged = false;
      }

    return m_size + m_header.size();
  }

  Ptr<Blob>
  DerComplex::getRaw()
  {
    Ptr<Blob> blob = Ptr<Blob>::Create();
    blob->insert(blob->end(), m_header.begin(), m_header.end());
    DerNodePtrList::iterator it = m_nodeList.begin();
    for(; it != m_nodeList.end(); it++)
      {
        Ptr<Blob> childBlob = (*it)->getRaw();
        blob->insert(blob->end(), childBlob->begin(), childBlob->end());
      }
    return blob;
  }

  void
  DerComplex::updateSize ()
  {
    int newSize = 0;

    DerNodePtrList::iterator it = m_nodeList.begin();
    for(; it != m_nodeList.end(); it++)
      {
	newSize += (*it)->getSize();
      }
    
    m_size = newSize;
    m_childChanged = false;
  }

  void
  DerComplex::addChild (Ptr<DerNode> nodePtr, bool notifyParent)
  {
    nodePtr->setParent(this);

    m_nodeList.push_back(nodePtr);

    if(!notifyParent)
      return;

    if(m_childChanged)
      return;
    else
      m_childChanged = true;

    if(NULL != m_parent)
      m_parent->setChildChanged();
  }

  void
  DerComplex::setChildChanged ()
  {
    if(NULL != m_parent && !m_childChanged)
      {
        m_parent->setChildChanged();
        m_childChanged = true;
      }
    else
      m_childChanged = true;
  }
  
  void
  DerComplex::encode (OutputIterator & start)
  {
    updateSize();

    DerNode::encodeHeader(m_size);

    start.write(m_header.buf(), m_header.size());

    DerNodePtrList::iterator it = m_nodeList.begin();
    for(; it != m_nodeList.end(); it++)
      (*it)->encode(start);
  }

}//der

}//ndn
