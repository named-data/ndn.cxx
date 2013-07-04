/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */


#ifndef NDN_REGEX_H
#define NDN_REGEX_H

#include "ndn.cxx/fields/name.h"

using namespace std;

namespace ndn{
  class Expression;

  class Regex{
  public:
    ///////////////////////////////////////////////////////////////////////////////
    //                              CONSTRUCTORS                                 //
    ///////////////////////////////////////////////////////////////////////////////
    /**
     * @brief Default constructor to create an empty regex ("")
     */
    Regex();

  private:
    string m_sRegex;
    Exression* m_expr;
  };

  class Expression{
  public:
  private:
    HeadPattern* m_head;
    Pattern* m_middle;
    TailPattern * m_tail;
  }


}//ndn


#endif
