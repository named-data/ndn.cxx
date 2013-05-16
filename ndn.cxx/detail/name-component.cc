/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil -*- */
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

#include "name-component.h"

#include "ndn.cxx/detail/error.h"
#include "ndn.cxx/detail/uri.h"

using namespace std;

namespace ndn
{
namespace name
{
  
Component::Component ()
{
}

Component::Component (const std::string &uri)
{
  try
    {
      Uri::fromEscaped (uri.begin (), uri.end (), back_inserter (*this));
    }
  catch (error::Uri &err)
    {
      // re-throwing different exception
      BOOST_THROW_EXCEPTION (error::name::Component ()
                             << error::msg (uri)
                             << error::pos (error::get_pos (err)));
    }
}

Component::Component (std::string::const_iterator begin, std::string::const_iterator end)
{
  try
    {
      Uri::fromEscaped (begin, end, back_inserter (*this));
    }
  catch (error::Uri &err)
    {
      // re-throwing different exception
      BOOST_THROW_EXCEPTION (error::name::Component ()
                             << error::msg (string (begin, end))
                             << error::pos (error::get_pos (err)));
    }
}

Component::Component (const void *buf, size_t length)
{
  copy (static_cast<const char*> (buf),
        static_cast<const char*> (buf)+length,
        back_inserter (*this));
}

int
Component::compare (const Component &other) const
{
  if (size () < other.size ())
    return -1;

  if (size () > other.size ())
    return +1;

  // now we know that sizes are equal

  pair<const_iterator, const_iterator> diff = mismatch (begin (), end (), other.begin ());
  if (diff.first == end ()) // components are actually equal
    return 0;

  return (std::lexicographical_compare (diff.first, end (), diff.second, other.end ())) ? -1 : +1;    
}

Component
Component::fromNumber (uint64_t number)
{
  Component comp;
  while (number > 0)
    {
      comp.push_back (static_cast<unsigned char> (number & 0xFF));
      number >>= 8;
    }
  return comp;
}

Component
Component::fromNumberWithMarker (uint64_t number, unsigned char marker)
{
  Component comp;
  comp.push_back (marker);

  while (number > 0)
    {
      comp.push_back (static_cast<unsigned char> (number & 0xFF));
      number >>= 8;
    }
  return comp;
}

std::string
Component::toBlob () const
{
  return std::string (begin (), end ());
}

void
Component::toBlob (std::ostream &os) const
{
  os.write (buf (), size ());
}

std::string
Component::toUri () const
{
  ostringstream os;
  toUri (os);
  return os.str ();  
}

void
Component::toUri (std::ostream &os) const
{
  Uri::toEscaped (begin (), end (), ostream_iterator<char> (os));
}

uint64_t
Component::toNumber () const
{
  uint64_t ret = 0;
  for (const_reverse_iterator i = rbegin (); i != rend (); i++)
    {
      ret <<= 8;
      ret |= *i;
    }
  return ret;
}

uint64_t
Component::toNumberWithMarker (unsigned char marker) const
{
  if (empty () ||
      *(begin ()) != marker)
    {
      BOOST_THROW_EXCEPTION (error::name::Component ()
                             << error::msg ("Name component does not have required marker")
                             << error::msg (toUri ()));
    }
  uint64_t ret = 0;
  const_reverse_iterator i = rbegin ();
  unsigned char value = *i;
  i++;
  for (; i != rend (); i++)
    {
      ret <<= 8;
      ret |= value;

      value = *i;
    }
  return ret;
}


} // name
} // ndn
