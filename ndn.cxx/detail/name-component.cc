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
#include "ndn.cxx/detail/string-transform.h"

#include <boost/lexical_cast.hpp>

// Exceptions
typedef boost::error_info<struct tag_errmsg, std::string> error_info_str;

using namespace std;

namespace ndn
{
namespace name
{

static const bool ESCAPE_CHARACTER [256] = {
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 26
  1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 53
  0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 80
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 107
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, // 134
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 161
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 188
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 215
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 242
  1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 // 255
};
  
Component::Component ()
{
}

Component::Component (const std::string &uri)
{
  string::const_iterator i = uri.begin ();
  while (i != uri.end ())
    {
      if (*i == '%')
        {
          try
            {
              i++;
              string::const_iterator j = i;
              advance (i, 2);
              
              copy (detail::string_to_binary (j), detail::string_to_binary (i), back_inserter (*this));
            }
          catch (ndn::error::StringTransform &e)
            {
              boost::throw_exception (error::name::Component ()
                                      << error_info_str ("Incorrect escape sequence in URI name: [" + uri + "] near position " +
                                                         boost::lexical_cast<string> (distance (i, uri.begin ()))));
            }
        }
      else if (!ESCAPE_CHARACTER[static_cast<unsigned short> (*i)])
        {
          push_back (*i);
          i++;
        }
      else
        {
          boost::throw_exception (error::name::Component ()
                                  << error_info_str ("Incorrect URI name: [" + uri + "]"));
        }
    }
}
  
Component::Component (const void *buf, size_t length)
{
  copy (static_cast<const char*> (buf),
        static_cast<const char*> (buf)+length,
        back_inserter (*this));
}

bool
Component::operator <= (const Component &other) const
{
  if (size () < other.size ())
    return true;

  if (size () > other.size ())
    return false;

  // now we know that sizes are equal

  pair<const_iterator, const_iterator> diff = mismatch (begin (), end (), other.begin ());
  if (diff.first == end ()) // components are actually equal
    return true;

  return std::lexicographical_compare (diff.first, end (), diff.second, other.end ());
}

std::ostream&
operator << (std::ostream &os, const Component &name)
{
  for (Component::const_iterator i = name.begin (); i != name.end (); i++)
    {
      if (ESCAPE_CHARACTER[static_cast<unsigned short> (*i)])
        {
          os << "%" << hex << setfill('0') << setw(2) << static_cast<unsigned int> (*i);
        }
      else
        {
          os << *i;
        }
    }
  return os;
}


} // name
} // ndn
