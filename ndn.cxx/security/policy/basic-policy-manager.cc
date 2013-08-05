/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "basic-policy-manager.h"
#include "identity-policy.h"

using namespace std;

namespace ndn
{

namespace security
{
  void 
  BasicPolicyManager::setSigningPolicy (const string & policyStr)
  {
    Ptr<Policy> policy = parsePolicy(policyStr);
    m_signPolicies.push_back(policy);
  }

  void 
  BasicPolicyManager::setSigningInference(const string & inferenceStr)
  {
    Ptr<Regex> inference = parseInference(inferenceStr);
    m_signInference.push_back(inference);
  }

  void 
  BasicPolicyManager::setVerificationPolicy (const string & policyStr)
  {
    Ptr<Policy> policy = parsePolicy(policyStr);
    if(policy->mustVerify())
      m_verifyPolicies.push_back(policy);
    else
      m_notVerifyPolicies.push_back(policy);
  }

  bool
  BasicPolicyManager::requireVerify (const Data & data)
  {
    vector< Ptr<Policy> >::iterator it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->matchDataName(data) || (*it)->matchSignerName(data))
	  return true;
      }

    return false;
  }

  bool 
  BasicPolicyManager::skipVerify (const Data & data)
  {
    vector< Ptr<Policy> >::iterator it = m_notVerifyPolicies.begin();
    for(; it != m_notVerifyPolicies.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    return false;
  }

  void 
  BasicPolicyManager::setTrustAnchor(const Certificate & certificate)
  {
    m_trustAnchors.insert(pair<const Name, const Certificate>(certificate.getName(), certificate));
  }

  Ptr<const Certificate>
  BasicPolicyManager::getTrustAnchor(const Name & name)
  {
    if(m_trustAnchors.end() == m_trustAnchors.find(name))
      return NULL;
    else
      return Ptr<const Certificate>(new Certificate(m_trustAnchors[name]));
  }

  bool 
  BasicPolicyManager::checkVerificationPolicy(const Data & data)
  {
    vector< Ptr<Policy> >::iterator it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->satisfy(data))
	  return true;
      }

    return false;
  }

  bool 
  BasicPolicyManager::checkSigningPolicy(const Name & dataName, const Name & certName)
  {
    vector< Ptr<Policy> >::iterator it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return true;
      }

    return false;
  }
  
  Name
  BasicPolicyManager::inferSigningCert(const Name & dataName)
  {
    vector< Ptr<Regex> >::iterator it = m_signInference.begin();
    for(; it != m_signInference.end(); it++)
      {
	if((*it)->match(dataName))
	  return (*it)->expand();
      }

    return Name();
  }

  string 
  BasicPolicyManager::replaceWS (const string & policy)
  {
    string result = policy;

    for(int i = 0; i < policy.size(); i++)
      {
	if(result[i] == '\t')
	  result[i] = ' ';
      }
    
    return result;
  }

  Ptr<Regex>
  BasicPolicyManager::parseInference (const string & inference)
  {
    string cInference = replaceWS(inference);

    int offset = 0;
      
    string dataRegex = getStringItem(inference, offset);

    if(string::npos == offset) 
      throw SecException("No identity expand!");

    string certExpand = getStringItem(inference, offset);
    
    return Ptr<Regex>(new Regex(dataRegex, certExpand));
  }

  Ptr<Policy>
  BasicPolicyManager::parsePolicy (const string & policy)
  {
    string cPolicy = replaceWS(policy);

    int offset = 0;

    string identityType = getStringItem(cPolicy, offset);

    if("IDENTITY_POLICY" == identityType){
      
      if(string::npos == offset) 
	throw SecException("No data regex!");

      string dataRegex = getStringItem(cPolicy, offset);


      if(string::npos == offset) 
	throw SecException("No data expand!");

      string dataExpand = getStringItem(cPolicy, offset);


      if(string::npos == offset) 
	throw SecException("No relation!");
      
      string op = getStringItem(cPolicy, offset);

      
      if(string::npos == offset) 
	throw SecException("No signer regex!");
      
      string signerRegex = getStringItem(cPolicy, offset);


      if(string::npos == offset) 
	throw SecException("No signer expand!");
      
      string signerExpand = getStringItem(cPolicy, offset);

      
      if(string::npos == offset) 
	throw SecException("No mustSign!");
      
      string mustVerifyStr = getStringItem(cPolicy, offset);

      bool mustVerify = true;
      
      if("NOVERIFY" == mustVerifyStr)
	mustVerify = false;
      

      return Ptr<Policy>(new IdentityPolicy(dataRegex, signerRegex, op, dataExpand, signerExpand, mustVerify));
    }
    else
      throw SecException("Unsupported policy type!");
  }
  
  string
  BasicPolicyManager::getStringItem (const string & policy, int & offset)
  {
    while(policy[offset] == ' ')
      {
	offset++;
      }
    int start = offset;

    offset = policy.find(' ', start);
    
    return policy.substr(start, offset - start);
  }

}//security

}//ndn
