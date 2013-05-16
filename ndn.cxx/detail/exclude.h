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

#ifndef NDN_EXCLUDE_H
#define NDN_EXCLUDE_H

#include "ndn.cxx/common.h"
#include "ndn.cxx/name.h"

namespace ndn {

/**
 * @brief Class to represent Exclude component in NDN interests
 */
class Exclude
{
public:
  typedef std::pair<Bytes /*component*/, bool /*any*/> item_type;
  typedef std::set<>
  
  /**
   * @brief Default constructor an empty exclude
   */
  Exclude ();

private:
  
};

typedef boost::shared_ptr<Exclude> ExcludePtr;

namespace Error
{
struct Exclude : public virtual boost::exception, public virtual std::exception {};

}

std::ostream&
operator <<(std::ostream &os, const Exclude &name);


} // ndn

#endif // NDN_EXCLUDE_H
