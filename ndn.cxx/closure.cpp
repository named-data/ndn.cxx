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
 * Author: Zhenkai Zhu <zhenkai@cs.ucla.edu>
 *         Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#include "closure.h"

namespace ndn {

Closure::Closure(const DataCallback &dataCallback, const TimeoutCallback &timeoutCallback)
  : m_timeoutCallback (timeoutCallback)
  , m_dataCallback (dataCallback)
{
}

Closure::~Closure ()
{
}

void
Closure::runTimeoutCallback(Name interest, const Closure &closure, InterestPtr origInterest)
{
  if (!m_timeoutCallback.empty ())
    {
      m_timeoutCallback (interest, closure, origInterest);
    }
}


void
Closure::runDataCallback(Name name, PcoPtr content)
{
  if (!m_dataCallback.empty ())
    {
      m_dataCallback (name, content);
    }
}

} // ndn
