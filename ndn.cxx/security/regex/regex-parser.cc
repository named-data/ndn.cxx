/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "regex-parser.h"
#include "regex-exception.h"

namespace ndn
{

namespace regex
{
  void RegexParser::Compile(const string & expr)
  {
    const int len = expr.size();
    int index = 0;
    int subHead = index;

    while(index < len){
      try{
        subHead = index;
        index = ExtractSubPattern(expr, index, len);
        cout << expr.substr(subHead, index - subHead) << endl;
      }
      catch(RegexException & e){
        cerr << e.GetMsg() << endl;
        exit(-1);
      }
    }
  }

  int RegexParser::ExtractSubPattern(const string & expr, int index, const int & len)
  {
    bool head = (index == 0 ? true : false);
    int end = index;

    switch(expr[index]){
    case '^':
      if(head){
	index++;
	end = ExtractSubPattern(expr, index, len);
        return CheckDollar(expr, end, len);
      }
      else
        throw RegexException("Error: ^ is not the first");

    case '(':
      index++;
      index = ExtractBackRef(expr, index, len);
      end = ExtractRepetition(expr, index, len);
      return CheckDollar(expr, end, len);

    case '!':
      index++;
      end = ExtractSubPattern(expr, index, len);
      return CheckDollar(expr, end, len);

    case '[':
      index++;
      index = ExtractComponent(expr, index, len);
      end = ExtractRepetition(expr, index, len);
      return CheckDollar(expr, end, len);

    default:
      throw RegexException("Error: unexpected syntax");
    }
  }

  int RegexParser::CheckDollar(const string & expr, int index, const int & len)
  {
    if('$' == expr[index]){

      if(len - 1 == index)
        return len;
      else
        throw RegexException("Error: pattern after $");
    }
    else
      return index;
  }
    
  int RegexParser::ExtractBackRef(const string & expr, int index, const int & len)
  {
    int lcount = 1;
    int rcount = 0;
    
    while(lcount > rcount){
      switch(expr[index]){
      case '(':
        lcount++;
        break;

      case ')':
        rcount++;
        break;

      case 0:
        throw RegexException("Error: parenthesis mismatch");
        break;
      }

      index++;
    }
    return index;
      
  }
  
  int RegexParser::ExtractComponent(const string & expr, int index, const int & len)
  {
    int lcount = 1;
    int rcount = 0;
    
    while(lcount > rcount){
      switch(expr[index]){
      case '[':
        lcount++;
        break;

      case ']':
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

  int RegexParser::ExtractRepetition(const string & expr, int index, const int & len)
  {    
    cerr << "repetition: " << index << endl;
    switch(expr[index]){
    case '*':
    case '+':
    case '?':
      return ++index;
    case '{':
      while('0' != expr[index]){
        index++;
        if('}' == expr[index])
          return ++index;
      }
      throw RegexException("Error: brace brackets mismatch");
    default:
      return index;
    }
  }
}//regex

}//ndn

