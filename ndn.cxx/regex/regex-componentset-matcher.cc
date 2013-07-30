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
    _LOG_DEBUG ("Enter RegexComponentSetMatcher Constructor: " << m_expr);
    if(!compile())
      throw RegexException("RegexComponentSetMatcher Constructor: Cannot compile the regex");
  }

  RegexComponentSetMatcher::~RegexComponentSetMatcher()
  {
    set<RegexComponent*>::iterator it = m_components.begin();

    for(; it != m_components.end(); it++)
      delete *it;
  }

  bool 
  RegexComponentSetMatcher::compile()
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::Compile()");
    _LOG_DEBUG ("expr: " << m_expr);

    string errMsg = "Error: RegexComponentSetMatcher.Compile(): ";
    int index = 0;


    switch(m_expr[0]){
    case '<':
      return compileSingleComponent();
    case '[':
      {
        int lastIndex = m_expr.size() - 1;
        if(']' != m_expr[lastIndex])
          throw RegexException(errMsg + " No matched ']' " + m_expr);

        if('^' == m_expr[1]){
          m_include = false;
          return compileMultipleComponents(2, lastIndex);
        }
        else
          return compileMultipleComponents(1, lastIndex);
      }
    default:
        throw RegexException(errMsg + "Parsing error in expr " + m_expr);
    }
  }

  bool 
  RegexComponentSetMatcher::compileSingleComponent()
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::CompileSingleComponent()");

    string errMsg = "Error: RegexComponentSetMatcher.CompileSingleComponent(): ";

    int end = extractComponent(1);

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

  bool 
  RegexComponentSetMatcher::compileMultipleComponents(const int start, const int lastIndex)
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::CompileMultipleComponents()");

    string errMsg = "Error: RegexComponentSetMatcher.CompileMultipleComponents(): ";

    int index = start;
    int tmp_index = start;
    
    while(index < lastIndex){
      if('<' != m_expr[index])
        throw RegexException(errMsg + "Component expr error " + m_expr);
      
      tmp_index = index + 1;
      index = extractComponent(tmp_index);

      RegexComponent* component = new RegexComponent(m_expr.substr(tmp_index, index - tmp_index - 1), m_backRefManager);
      m_components.insert(component);
    }
    
    if(index == lastIndex)
      return true;
    else
      throw RegexException(errMsg + "Not sufficient expr to parse " + m_expr);        
  }


  bool 
  RegexComponentSetMatcher::match(Name name, const int & offset, const int & len)
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
      if((*it)->match(name, offset, len)){
        matched = true;
        break;
      }
    }
    
    m_matchResult = Name();

    if(m_include ? matched : !matched){
      m_matchResult.append(name.get(offset));
      return true;
    }
    else 
      return false;
  }

  int 
  RegexComponentSetMatcher::extractComponent(int index)
  {
    _LOG_DEBUG ("Enter RegexComponentSetMatcher::ExtractComponent");

    int lcount = 1;
    int rcount = 0;

    while(lcount > rcount){
      switch(m_expr[index]){
      case '<':
        lcount++;
        break;

      case '>':
        rcount++;
        break;

      case 0:
        throw RegexException("Error: square brackets mismatch");
        break;
      }
      index++;

    }
    return index;

  }

}//regex

}//ndn
