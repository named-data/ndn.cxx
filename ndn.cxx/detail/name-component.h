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
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_NAME_COMPONENT_H
#define NDN_NAME_COMPONENT_H

#include <boost/exception/all.hpp>

#include <string>
#include <vector>

namespace ndn {

namespace name {

/**
 * @brief Class to representing binary blob of NDN name component
 *
 * This class is based on std::vector<char> and just provides several helpers
 * to work with name components, as well as operator to apply canonical
 * ordering on name components
 */
class Component : public std::vector<char>
{
public:
  /**
   * @brief Default constructor an empty exclude
   */
  Component ();

  /**
   * @brief Create component from URI encoded string
   * @param uri URI encoded name component (convert escaped with % characters)
   */
  Component (const std::string &uri);
  
  /**
   * @brief Create component using a binary blob
   * @param buf pointer to first byte of binary blob to store as a name component
   * @param length length of the binary blob
   */
  Component (const void *buf, size_t length);

  /**
   * @brief Apply canonical ordering on component comparison
   *
   * @see http://www.ccnx.org/releases/latest/doc/technical/CanonicalOrder.html
   */
  bool
  operator <= (const Component &other) const;
};

namespace error { namespace name { 
struct Component : public virtual boost::exception, public virtual std::exception {};
}}

std::ostream&
operator <<(std::ostream &os, const Component &name);

} // name

} // ndn

#endif // NDN_EXCLUDE_H
