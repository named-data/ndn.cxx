/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#ifndef NDN_REGEX_PARSER_H
#define NDN_REGEX_PARSER_H

#include "regex-matcher.h"
#include "regex-exception.h"
#include <string>

using namespace std;

namespace ndn
{

namespace regex
{
  class RegexParser{
  public:
    static void Compile(const string & expr);
  private:
    static int ExtractSubPattern(const string & expr, int index, const int & len);
    static int CheckDollar(const string & expr, int index, const int & len);
    static int ExtractBackRef(const string & expr, int index, const int & len);
    static int ExtractComponent(const string & expr, int index, const int & len);
    static int ExtractRepetition (const string & expr, int index, const int & len);
  };

}//regex

}//ndn


#endif
