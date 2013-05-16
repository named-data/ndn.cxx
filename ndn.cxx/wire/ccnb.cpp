/* -*- Mode: C++; c-file-style: "gnu"; tab-width: 4; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013 University of California, Los Angeles
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
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "ccnb.h"
#include <boost/lexical_cast.hpp>

namespace ndn
{

#define CCN_TT_BITS 3
#define CCN_TT_MASK ((1 << CCN_TT_BITS) - 1)
#define CCN_MAX_TINY ((1 << (7-CCN_TT_BITS)) - 1)
#define CCN_TT_HBIT ((unsigned char)(1 << 7))

size_t
Ccnb::AppendBlockHeader (std::ostream &os, size_t val, Ccnb::ccn_tt tt)
{
  unsigned char buf[1+8*((sizeof(val)+6)/7)];
  unsigned char *p = &(buf[sizeof(buf)-1]);
  size_t n = 1;
  p[0] = (CCN_TT_HBIT & ~Ccnb::CCN_CLOSE_TAG) |
  ((val & CCN_MAX_TINY) << CCN_TT_BITS) |
  (CCN_TT_MASK & tt);
  val >>= (7-CCN_TT_BITS);
  while (val != 0) {
    (--p)[0] = (((unsigned char)val) & ~CCN_TT_HBIT) | Ccnb::CCN_CLOSE_TAG;
    n++;
    val >>= 7;
  }
  os.write (reinterpret_cast<const char*> (p), n);
  return n;
}

size_t
Ccnb::AppendNumber (std::ostream &os, uint32_t number)
{
  std::string numberStr = boost::lexical_cast<std::string> (number);

  size_t written = 0;
  written += AppendBlockHeader (os, numberStr.size (), Ccnb::CCN_UDATA);
  written += numberStr.size ();
  os.write (numberStr.c_str (), numberStr.size ());

  return written;
}
  
size_t
Ccnb::AppendName (std::ostream &os, const Name &name)
{
  size_t written = 0;
  written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_Name, Ccnb::CCN_DTAG); // <Name>
  for (Name::const_iterator component = name.begin (); component != name.end (); component ++)
    {
      written += AppendTaggedBlob (os, Ccnb::CCN_DTAG_Component, component->buf (), component->size ());
    }
  written += Ccnb::AppendCloser (os);                                        // </Name>
  
  return written;
}

size_t
Ccnb::AppendTimestampBlob (std::ostream &os, const boost::posix_time::time_duration &time)
{
  // the original function implements Markers... thought not sure what are these markers for...

  // Determine miminal number of bytes required to store the timestamp
  int required_bytes = 2; // 12 bits for fractions of a second, 4 bits left for seconds. Sometimes it is enough
  intmax_t ts = time.total_seconds () >> 4;
  for (;  required_bytes < 7 && ts != 0; ts >>= 8) // not more than 6 bytes?
     required_bytes++;
  
  size_t len = AppendBlockHeader(os, required_bytes, Ccnb::CCN_BLOB);

  // write part with seconds
  ts = time.total_seconds () >> 4;
  for (int i = 0; i < required_bytes - 2; i++)
    os.put ( ts >> (8 * (required_bytes - 3 - i)) );

  /* arithmetic contortions are to avoid overflowing 31 bits */
  ts = ((time.total_seconds () & 15) << 12) +
    (((time.total_nanoseconds () % 1000000000) / 5 * 8 + 195312) / 390625);
  for (int i = required_bytes - 2; i < required_bytes; i++)
    os.put ( ts >> (8 * (required_bytes - 1 - i)) );
  
  return len + required_bytes;
}

size_t
Ccnb::AppendExclude (std::ostream &os, const Exclude &exclude)
{
  size_t written = 0;
  written += AppendBlockHeader (os, Ccnb::CCN_DTAG_Exclude, Ccnb::CCN_DTAG); // <Exclude>

  for (Exclude::const_reverse_iterator item = exclude.rbegin (); item != exclude.rend (); item ++)
    {
      if (!item->first.empty ())
        written += AppendTaggedBlob (os, Ccnb::CCN_DTAG_Component, item->first.buf (), item->first.size ());
      if (item->second)
        {
          written += AppendBlockHeader (os, Ccnb::CCN_DTAG_Any, Ccnb::CCN_DTAG); // <Any>
          written += AppendCloser (os); // </Any>
        }
    }
  written += AppendCloser (os); // </Exclude>

  return written;
}

size_t
Ccnb::AppendInterest (std::ostream &os, const Interest &interest)
{
  size_t written = 0;
  written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_Interest, Ccnb::CCN_DTAG); // <Interest>

  // this is used for now as an interest template. Name should be empty
  // written += Ccnb::AppendName (os, interest.getName ());
  written += Ccnb::AppendName (os, Name ());                              // <Component>...</Component>...

  if (interest.getMinSuffixComponents () != Interest::ncomps)
    {
      written += AppendTaggedNumber (os, Ccnb::CCN_DTAG_MinSuffixComponents, interest.getMinSuffixComponents ());
    }
  if (interest.getMaxSuffixComponents () != Interest::ncomps)
    {
      written += AppendTaggedNumber (os, Ccnb::CCN_DTAG_MaxSuffixComponents, interest.getMaxSuffixComponents ());
    }
  if (interest.getExclude ().size () > 0)
    {
      written += AppendExclude (os, interest.getExclude ());
    }
  if (interest.getChildSelector () != Interest::CHILD_DEFAULT)
    {
      written += AppendTaggedNumber (os, Ccnb::CCN_DTAG_ChildSelector, interest.getChildSelector ());
    }
  if (interest.getAnswerOriginKind () != Interest::AOK_DEFAULT)
    {
      written += AppendTaggedNumber (os, Ccnb::CCN_DTAG_AnswerOriginKind, interest.getAnswerOriginKind ());
    }
  if (interest.getScope () != Interest::NO_SCOPE)
    {
      written += AppendTaggedNumber (os, Ccnb::CCN_DTAG_Scope, interest.getScope ());
    }
  if (!interest.getInterestLifetime ().is_negative ())
    {
      written += Ccnb::AppendBlockHeader (os, Ccnb::CCN_DTAG_InterestLifetime, Ccnb::CCN_DTAG);
      written += Ccnb::AppendTimestampBlob (os, interest.getInterestLifetime ());
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

  return written;
}


} // namespace ndn
