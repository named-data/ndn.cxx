/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2012-2013 University of California, Los Angeles
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *	   Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "interest.h"
#include <boost/lexical_cast.hpp>
#include <ndn.cxx/ccnb.h>

using namespace std;

namespace ndn {

Interest::Interest ()
  // m_name
  : m_maxSuffixComponents (Interest::ncomps)
  , m_minSuffixComponents (Interest::ncomps)
  , m_answerOriginKind (AOK_DEFAULT)
  , m_interestLifetime (boost::posix_time::seconds (-1.0))
  , m_scope (NO_SCOPE)
  , m_childSelector (CHILD_DEFAULT)
  // m_publisherKeyDigest
{
}

Interest::Interest (const Name &name)
  : m_name (name)
  , m_maxSuffixComponents (Interest::ncomps)
  , m_minSuffixComponents (Interest::ncomps)
  , m_answerOriginKind(AOK_DEFAULT)
  , m_interestLifetime (boost::posix_time::seconds (-1.0))
  , m_scope (NO_SCOPE)
  , m_childSelector (CHILD_DEFAULT)
  // m_publisherKeyDigest
{
}

Interest::Interest (const Interest &other)
{
  m_name = other.m_name;
  m_maxSuffixComponents = other.m_maxSuffixComponents;
  m_minSuffixComponents = other.m_minSuffixComponents;
  m_answerOriginKind = other.m_answerOriginKind;
  m_interestLifetime = other.m_interestLifetime;
  m_scope = other.m_scope;
  m_childSelector = other.m_childSelector;
  m_publisherPublicKeyDigest = other.m_publisherPublicKeyDigest;
}

Interest::Interest (const ccn_parsed_interest *pi)
  : m_maxSuffixComponents (Interest::ncomps)
  , m_minSuffixComponents (Interest::ncomps)
  , m_answerOriginKind (AOK_DEFAULT)
  , m_interestLifetime (boost::posix_time::seconds (-1.0))
  , m_scope (NO_SCOPE)
  , m_childSelector (CHILD_DEFAULT)
{
  if (pi != NULL)
  {
    m_maxSuffixComponents = pi->max_suffix_comps;
    m_minSuffixComponents = pi->min_suffix_comps;
    switch(pi->orderpref)
      {
      case 0: m_childSelector = CHILD_LEFT; break;
      case 1: m_childSelector = CHILD_RIGHT; break;
      default: m_childSelector = CHILD_DEFAULT; break;
      }
    
    switch(pi->answerfrom)
    {
      case 0x1: m_answerOriginKind = AOK_CS; break;
      case 0x2: m_answerOriginKind = AOK_NEW; break;
      case 0x3: m_answerOriginKind = AOK_DEFAULT; break;
      case 0x4: m_answerOriginKind = AOK_STALE; break;
      case 0x10: m_answerOriginKind = AOK_EXPIRE; break;
      default: break;
    }
    m_scope = static_cast<Scope> (pi->scope);
  }

  /// @todo copy publisher key digest
}

bool
Interest::operator == (const Interest &other)
{
  return
       m_name == other.m_name
    && m_maxSuffixComponents == other.m_maxSuffixComponents
    && m_minSuffixComponents == other.m_minSuffixComponents
    && m_answerOriginKind == other.m_answerOriginKind
    && m_interestLifetime == other.m_interestLifetime
    && m_scope == other.m_scope
    && m_childSelector == other.m_childSelector;
}


CharbufPtr
Interest::toCharbuf() const
{
  CharbufPtr ptr(new Charbuf());
  ccn_charbuf *cbuf = ptr->getBuf();
  ccn_charbuf_append_tt(cbuf, CCN_DTAG_Interest, CCN_DTAG);
  ccn_charbuf_append_tt(cbuf, CCN_DTAG_Name, CCN_DTAG);

  // not necessary. the resulting charbuf is used as a template
  // ccn_charbuf_append_charbuf(cbuf, getName ().toCharbuf ()->getBuf ());
  
  ccn_charbuf_append_closer(cbuf); // </Name>

  if (m_maxSuffixComponents < m_minSuffixComponents)
  {
    boost::throw_exception(InterestException() << error_info_str("MaxSuffixComps = " + boost::lexical_cast<string>(m_maxSuffixComponents) + " is smaller than  MinSuffixComps = " + boost::lexical_cast<string>(m_minSuffixComponents)));
  }

  if (m_minSuffixComponents != Interest::ncomps)
  {
    ccnb_tagged_putf(cbuf, CCN_DTAG_MinSuffixComponents, "%d", m_minSuffixComponents);
  }

  if (m_maxSuffixComponents != Interest::ncomps)
  {
    ccnb_tagged_putf(cbuf, CCN_DTAG_MaxSuffixComponents, "%d", m_maxSuffixComponents);
  }

  // publisher digest

  // exclude

  if (m_childSelector != CHILD_DEFAULT)
  {
    ccnb_tagged_putf(cbuf, CCN_DTAG_ChildSelector, "%d", (int)m_childSelector);
  }
  
  if (m_answerOriginKind != AOK_DEFAULT)
  {
    // it was not using "ccnb_tagged_putf" in ccnx c code, no idea why
    ccn_charbuf_append_tt(cbuf, CCN_DTAG_AnswerOriginKind, CCN_DTAG);
    ccnb_append_number(cbuf, m_answerOriginKind);
    ccn_charbuf_append_closer(cbuf); // <AnswerOriginKind>
  }

  if (m_scope != NO_SCOPE)
  {
    ccnb_tagged_putf(cbuf, CCN_DTAG_Scope, "%d", m_scope);
  }

  if (!m_interestLifetime.is_negative ())
  {
    double interestLifetime = m_interestLifetime.total_seconds () + (m_interestLifetime.total_microseconds () / 1000000.0);
    
    // ndn timestamp unit is weird 1/4096 second
    // this is from their code
    unsigned lifetime = 4096 * (interestLifetime + 1.0/8192.0);
    if (lifetime == 0 || lifetime > (30 << 12))
    {
      boost::throw_exception (InterestException() << error_info_str("ndn requires 0 < lifetime < 30.0. lifetime= " + boost::lexical_cast<string>(interestLifetime)));
    }
    unsigned char buf[3] = {0};
    for (int i = sizeof(buf) - 1; i >= 0; i--, lifetime >>= 8)
    {
      buf[i] = lifetime & 0xff;
    }
    ccnb_append_tagged_blob(cbuf, CCN_DTAG_InterestLifetime, buf, sizeof(buf));
  }

  ccn_charbuf_append_closer(cbuf); // </Interest>

  return ptr;
}

std::ostream &
Interest::toWire (std::ostream &os)
{
  size_t written = 0;
  written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_Interest, Ccnb::CCN_DTAG); // <Interest>
  
  written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_Name, Ccnb::CCN_DTAG); // <Name>
  written += Ccnb::AppendName (os, getName ());                              // <Component>...</Component>...
  written += Ccnb::AppendCloser (os);                                        // </Name>

  if (getMinSuffixComponents () != Interest::ncomps)
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_MinSuffixComponents, Ccnb::CCN_DTAG);
      written += Ccnb::AppendNumber (os, getMinSuffixComponents ());
      written += Ccnb::AppendCloser (os);
    }
  if (getMaxSuffixComponents () != Interest::ncomps)
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_MaxSuffixComponents, Ccnb::CCN_DTAG);
      written += Ccnb::AppendNumber (os, getChildSelector ());
      written += Ccnb::AppendCloser (os);
    }
  // if (IsEnabledExclude() && interest.GetExclude().size() > 0)
  //   {
  //     written += AppendBlockHeader (start, Ccnb::CCN_DTAG_Exclude, Ccnb::CCN_DTAG); // <Exclude>
  //     written += AppendName (start, interest.GetExclude());                // <Component>...</Component>...
  //     written += AppendCloser (start);                                  // </Exclude>
  //   }
  if (getChildSelector () != CHILD_DEFAULT)
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_ChildSelector, Ccnb::CCN_DTAG);
      written += Ccnb::AppendNumber (os, getChildSelector ());
      written += Ccnb::AppendCloser (os);
    }
  if (getAnswerOriginKind () != AOK_DEFAULT)
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_AnswerOriginKind, Ccnb::CCN_DTAG);
      written += Ccnb::AppendNumber (os, getAnswerOriginKind ());
      written += Ccnb::AppendCloser (os);
    }
  if (getScope () != NO_SCOPE)
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_Scope, Ccnb::CCN_DTAG);
      written += Ccnb::AppendNumber (os, getScope ());
      written += Ccnb::AppendCloser (os);
    }
  if (!getInterestLifetime ().is_negative ())
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_InterestLifetime, Ccnb::CCN_DTAG);
      written += Ccnb::AppendTimestampBlob (os, getInterestLifetime ());
      written += Ccnb::AppendCloser (os);
    }
  // if (GetNonce()>0)
  //   {
  //     uint32_t nonce = interest.GetNonce();
  //     written += AppendTaggedBlob (start, Ccnb::CCN_DTAG_Nonce, nonce);
  //   }
    
  // if (GetNack ()>0)
  //   {
  //     written += AppendBlockHeader (start, Ccnb::CCN_DTAG_Nack, Ccnb::CCN_DTAG);
  //     written += AppendNumber (start, interest.GetNack ());
  //     written += AppendCloser (start);
  //   }
  written += Ccnb::AppendCloser (os); // </Interest>

  return os;
}


} // ndn
