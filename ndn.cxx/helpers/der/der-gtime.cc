/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "der-gtime.h"

#include "ndn.cxx/security/exception.h"

#include <boost/date_time/posix_time/posix_time.hpp>

namespace ndn
{

namespace der
{
  DerGtime::DerGtime(const Time & time)
    :DerNode(DER_GENERALIZED_TIME)
  {
    string pTimeStr = boost::posix_time::to_iso_string(time);
    int index = pTimeStr.find_first_of('T');
    string derTime = pTimeStr.substr(0, index) + pTimeStr.substr(index+1, pTimeStr.size() - index -1) + "Z";
    m_payload.insert(m_payload.end(), derTime.begin(), derTime.end());

    DerNode::encodeHeader(m_payload.size());
  }

  DerGtime::DerGtime(InputIterator &start)
    :DerNode(start)
  {}
    
  DerGtime::~DerGtime()
  {}

}//der

}//ndn
