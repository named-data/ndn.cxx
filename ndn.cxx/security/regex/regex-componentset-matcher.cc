/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-componentset-matcher.h"

#include "logging.h"

INIT_LOGGER ("RegexComponentSetMatcher");

using namespace std;

namespace ndn
{

namespace regex
{
  RegexComponentSetMatcher::RegexComponentSetMatcher(const string expr, RegexBRManager *const backRefManager, bool include)
    : RegexMatcher(expr, EXPR_COMPONENT_SET, backRefManager),
      m_include(include)
  {
    _LOG_DEBUG ("Enter RegexComponent Constructor");
    if(!Compile())
      throw RegexException("RegexComponentSetMatcher Constructor: Cannot compile the regex");
  }

  RegexComponentSetMatcher::~RegexComponentSetMatcher()
  {
    set<RegexComponent*>::iterator it = m_components.begin();

    for(; it != m_components.end(); it++)
      delete *it;
  }

  bool RegexComponentSetMatcher::Compile()
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::Compile()");
    _LOG_DEBUG ("expr: " << m_expr);

    string errMsg = "Error: RegexComponentSetMatcher.Compile(): ";
    int index = 0;


    switch(m_expr[0]){
    case '<':
      return CompileSingleComponent();
    case '[':
      {
        int lastIndex = m_expr.size() - 1;
        if(']' != m_expr[lastIndex])
          throw RegexException(errMsg + " No matched ']' " + m_expr);

        if('^' == m_expr[1]){
          m_include = false;
          return CompileMultipleComponents(2, lastIndex);
        }
        else
          return CompileMultipleComponents(1, lastIndex);
      }
    default:
        throw RegexException(errMsg + "Parsing error in expr " + m_expr);
    }
  }

  bool RegexComponentSetMatcher::CompileSingleComponent()
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::CompileSingleComponent()");

    string errMsg = "Error: RegexComponentSetMatcher.CompileSingleComponent(): ";

    int end = ExtractComponent(1);

    if(m_expr.size() != end)
      throw RegexException(errMsg + m_expr);
    else{
      _LOG_DEBUG ("expr: " << m_expr.substr(1, end - 2));
      RegexComponent* component = new RegexComponent(m_expr.substr(1, end - 2), m_backRefManager);
      m_components.insert(component);
      return true;
    }

    return false;
  }

  bool RegexComponentSetMatcher::CompileMultipleComponents(const int start, const int lastIndex)
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::CompileMultipleComponents()");

    string errMsg = "Error: RegexComponentSetMatcher.CompileMultipleComponents(): ";

    int index = start;
    int tmp_index = start;
    
    while(index < lastIndex){
      if('<' != m_expr[index])
        throw RegexException(errMsg + "Component expr error " + m_expr);
      
      tmp_index = index + 1;
      index = ExtractComponent(tmp_index);

      RegexComponent* component = new RegexComponent(m_expr.substr(tmp_index, index - tmp_index - 1), m_backRefManager);
      m_components.insert(component);
    }
    
    if(index == lastIndex)
      return true;
    else
      throw RegexException(errMsg + "Not sufficient expr to parse " + m_expr);        
  }


  bool RegexComponentSetMatcher::Match(Name name, const int & offset, const int & len)
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::Match");

    bool matched = false;

    /* componentset only matches one component */
    if(len != 1){
      _LOG_DEBUG ("Match Fail: ComponentSet matches only one component");
      return false;
    }

    set<RegexComponent*>::iterator it = m_components.begin();

    for(; it != m_components.end(); it++){
      if((*it)->Match(name, offset, len)){
        matched = true;
        break;
      }
    }
    return (m_include ? matched : !matched);
  }

}//regex

}//ndn
