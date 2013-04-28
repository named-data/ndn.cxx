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

#ifndef CCNX_CLOSURE_H
#define CCNX_CLOSURE_H

#include "ccnx-cpp/common.h"
#include "ccnx-cpp/name.h"
#include "ccnx-cpp/selectors.h"

namespace Ccnx {

class ParsedContentObject;
typedef boost::shared_ptr<ParsedContentObject> PcoPtr;

class Closure
{
public:
  typedef boost::function<void (Name, PcoPtr pco)> DataCallback;

  typedef boost::function<void (Name, const Closure &, Selectors)> TimeoutCallback;

  Closure(const DataCallback &dataCallback, const TimeoutCallback &timeoutCallback = TimeoutCallback());
  virtual ~Closure();

  virtual void
  runDataCallback(Name name, Ccnx::PcoPtr pco);

  virtual void
  runTimeoutCallback(Name interest, const Closure &closure, Selectors selectors);

  virtual Closure *
  dup () const { return new Closure (*this); }

public:
  TimeoutCallback m_timeoutCallback;
  DataCallback m_dataCallback;
};

} // Ccnx

#endif
