/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <stdlib.h>

#include "regex-top-matcher.h"
#include "regex-patternlist-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexTopMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexTopMatcher::RegexTopMatcher(const string expr, RegexBRManager *const backRefManager, const string rule)
    : RegexMatcher(expr, EXPR_TOP, backRefManager),
      m_rule(rule)
  {
    m_backRefManager = new RegexBRManager();

    _LOG_DEBUG ("Enter RegexTopMatcher Constructor: " << m_expr);
    if(!Compile())
      throw RegexException("RegexTopMatcher Constructor: Cannot compile the regex");
  }

  RegexTopMatcher::~RegexTopMatcher()
  {
    delete m_backRefManager;
  }

  bool RegexTopMatcher::Compile()
  {
    _LOG_DEBUG ("Enter RegexTopMatcher::Compile()");

    string errMsg = "Error: RegexTopMatcher.Compile(): ";

    string expr = m_expr;
    if('^' != expr[0])
      expr = "<.*>*" + expr;
    else
      expr = expr.substr(1, expr.size()-1);

    if('$' != expr[expr.size() - 1])
      expr = expr + "<.*>*";
    else
      expr = expr.substr(0, expr.size()-1);

    _LOG_DEBUG ("reconstructed expr: " << expr);

    RegexPatternListMatcher * matcher = new RegexPatternListMatcher(expr, m_backRefManager);
    m_matcherList.push_back(matcher);
    return true;
  }

  bool RegexTopMatcher::MatchName(Name name)
  {
    return Match(name, 0, name.size());
  }
  
  bool RegexTopMatcher::MatchRule(Name name, Name target)
  {
    if(m_rule == "")
      throw RegexException("RegexTopMatcher::MatchRule: No rule set");
    
    if(!MatchName(name))
      throw RegexException("RegexTopMatcher::MatchRule: name does not match");

    int index = 0;
    int ruleSize = m_rule.size();
    int end = 0;
    
    Name rcName;

    while(index < ruleSize){
      RegexTgtCmptType cType = ParseRule(index, &end);
      if(cType == TCT_COMPONENT)
        rcName.append(m_rule.substr(index + 1, end - index - 2));
      if(cType == TCT_REFERENCE){
        int refNum = atoi(m_rule.substr(index+1, end - index - 2).c_str());
        rcName.append(m_backRefManager->GetBackRef(refNum)->GetMatchResult());
      }
      index = end;
    }
    
    return (rcName == target);
  }

  RegexTgtCmptType RegexTopMatcher::ParseRule(int index, int * end)
  {
    int ruleSize = m_rule.size();
    RegexTgtCmptType type; 
    
    if(index >= ruleSize)
      return TCT_END;

    switch(m_rule[index]){
    case '<':{
      index++;
      while(index < ruleSize){
        if('>' == m_rule[index]){
          *end = index+1;
          return TCT_COMPONENT;
        }
        index++;
      }
      if(index == ruleSize)
        throw RegexException("RegexTopMatcher::ParseRule: no matched >");
      break;
    }
    case '\\':{
      index++;
      while(index < ruleSize){
        if('0' >= m_rule[index] && '9' <= m_rule[index]){
          *end = index;
          return TCT_REFERENCE;
        }
        index++;
      }
      *end = index;
      return TCT_REFERENCE;
    }
    default:
      throw RegexException("RegexTopMatcher::ParseRule: unknown syntax");
    }
  }

}//regex

}//ndn
