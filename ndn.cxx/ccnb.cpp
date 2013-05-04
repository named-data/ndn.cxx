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

#define NDN_DETAIL_NEED_UNDEFINE_CCN_CLOSE 1

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
  p[0] = (CCN_TT_HBIT & ~Ccnb::CCN_CLOSE) |
  ((val & CCN_MAX_TINY) << CCN_TT_BITS) |
  (CCN_TT_MASK & tt);
  val >>= (7-CCN_TT_BITS);
  while (val != 0) {
    (--p)[0] = (((unsigned char)val) & ~CCN_TT_HBIT) | Ccnb::CCN_CLOSE;
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
Ccnb::AppendCloser (std::ostream &os)
{
  os.put (Ccnb::CCN_CLOSE);
  return 1;
}

size_t
Ccnb::AppendName (std::ostream &os, const Name &name)
{
  size_t written = 0;
  for (Name::const_iterator component = name.begin (); component != name.end (); component ++)
    {
      written += AppendTaggedBlob (os, Ccnb::CCN_DTAG_Component, head (*component), component->size ());
    }
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
Ccnb::AppendTaggedBlob (std::ostream &os, Ccnb::ccn_dtag dtag, const uint8_t *data, size_t size)
{
  size_t written = AppendBlockHeader (os, dtag, Ccnb::CCN_DTAG);
  /* 2 */
  if (size>0)
    {
      written += AppendBlockHeader (os, size, Ccnb::CCN_BLOB);
      os.write (reinterpret_cast<const char*> (data), size);
      written += size;
      /* size */
    }
  written += AppendCloser (os);
  /* 1 */

  return written;
}

size_t
Ccnb::AppendString (std::ostream &os, Ccnb::ccn_dtag dtag, const std::string &string)
{
  size_t written = AppendBlockHeader (os, dtag, Ccnb::CCN_DTAG);
  {
    written += AppendBlockHeader (os, string.size (), Ccnb::CCN_UDATA);
    os.write (string.c_str (), string.size ());
    written += string.size ();
  }
  written += AppendCloser (os);

  return written;
}

} // namespace ndn
