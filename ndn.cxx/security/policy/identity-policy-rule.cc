/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "ndn.cxx/security/exception.h"

#include "identity-policy-rule.h"

#include "logging.h"

INIT_LOGGER ("ndn.security.IdentityPolicyRule");

using namespace std;


namespace ndn
{

namespace security
{
  IdentityPolicyRule::IdentityPolicyRule (const string & dataRegex, const string & signerRegex, const string & op, 
				  const string & dataExpand, const string & signerExpand, bool isPositive)
    :PolicyRule(PolicyRule::IDENTITY_POLICY, isPositive),
     m_dataRegex(dataRegex),
     m_signerRegex(signerRegex),
     m_op(op),
     m_dataExpand(dataExpand),
     m_signerExpand(signerExpand),
     m_dataNameRegex(dataRegex, dataExpand),
     m_signerNameRegex(signerRegex, signerExpand)
  {
    if(op != ">" && op != ">=" && op != "==")
      throw SecException("op is wrong!");
  }

  IdentityPolicyRule::~IdentityPolicyRule()
  {
  }

  bool 
  IdentityPolicyRule::satisfy (const Data & data)
  {
    Name dataName = data.getName ();
    
    DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType && DIGEST_SHA256 == digestAlg)
      {
	Ptr<const signature::Sha256WithRsa> sigPtr = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
	Name signerName = sigPtr->getKeyLocator ().getKeyName ();
        
        return satisfy (dataName, signerName);
      }
       
    return false;
  }
  
  bool 
  IdentityPolicyRule::satisfy (const Name & dataName, const Name & signerName)
  {
    // _LOG_DEBUG("Rule: " << *toXmlElement());
    // _LOG_DEBUG("dataName: "  << dataName << " signerName: " << signerName);

    if(!m_dataNameRegex.match(dataName))
       return false;
    Name expandDataName = m_dataNameRegex.expand();

    if(!m_signerNameRegex.match(signerName))
      return false;
    Name expandSignerName =  m_signerNameRegex.expand();

    bool matched = compare(expandDataName, expandSignerName);
    
    // _LOG_DEBUG("DataName: " << expandDataName << " SignerName: " << expandSignerName << " Matched: " << matched);

    return matched;
  }

  TiXmlElement *
  IdentityPolicyRule::toXmlElement()
  {
    TiXmlElement * policy = new TiXmlElement("IdentityPolicyRule");
    
    TiXmlElement * dataRegex = new TiXmlElement("DataRegex");
    dataRegex->LinkEndChild(new TiXmlText(m_dataRegex));
    policy->LinkEndChild(dataRegex);

    TiXmlElement * signerRegex = new TiXmlElement("SignerRegex");
    signerRegex->LinkEndChild(new TiXmlText(m_signerRegex));
    policy->LinkEndChild(signerRegex);

    TiXmlElement * op = new TiXmlElement("Op");
    op->LinkEndChild(new TiXmlText(m_op));
    policy->LinkEndChild(op);

    TiXmlElement * dataExpand = new TiXmlElement("DataExpand");
    dataExpand->LinkEndChild(new TiXmlText(m_dataExpand));
    policy->LinkEndChild(dataExpand);

    TiXmlElement * signerExpand = new TiXmlElement("SignerExpand");
    signerExpand->LinkEndChild(new TiXmlText(m_signerExpand));
    policy->LinkEndChild(signerExpand);

    TiXmlElement * isPositive = new TiXmlElement("IsPositive");
    isPositive->LinkEndChild(new TiXmlText( (this->isPositive()? "1" : "0")));
    policy->LinkEndChild(isPositive);
    
    return policy;
  }

  Ptr<IdentityPolicyRule>
  IdentityPolicyRule::fromXmlElement(TiXmlElement * element)
  {
    TiXmlNode * it = element->FirstChild();

    string dataRegex;
    string signerRegex;
    string op;
    string dataExpand;
    string signerExpand;
    bool isPositive = true;
    while(it != NULL)
      {
        if(it->ValueStr() == string("DataRegex"))
          dataRegex = it->FirstChild()->ValueStr();
        else if(it->ValueStr() == string("SignerRegex"))
          signerRegex = it->FirstChild()->ValueStr();
        else if(it->ValueStr() == string("Op"))
          op = it->FirstChild()->ValueStr();
        else if(it->ValueStr() == string("DataExpand"))
          dataExpand = it->FirstChild()->ValueStr();
        else if(it->ValueStr() == string("SignerExpand"))
          signerExpand = it->FirstChild()->ValueStr();
        else if(it->ValueStr() == string("MustVerify"))
          {
            string mv = it->FirstChild()->ValueStr();
            if(mv == string("0"))
              isPositive = false;
          }
        it = it->NextSibling();
      }
    
    // _LOG_DEBUG(" " << dataRegex << " " << signerRegex << " " << op << " " << dataExpand << " " << signerExpand << " " << boolalpha << isPositive );

    return Ptr<IdentityPolicyRule>(new IdentityPolicyRule (dataRegex, signerRegex, op, dataExpand, signerExpand, isPositive));
  }


  bool 
  IdentityPolicyRule::matchDataName (const Data & data)
  {
    return m_dataNameRegex.match(data.getName ());
  }

  bool
  IdentityPolicyRule::matchSignerName (const Data & data)
  {    
    DigestAlgorithm digestAlg = DIGEST_SHA256; //For temporary, should be assigned by Signature.getAlgorithm();
    KeyType keyType = KEY_TYPE_RSA; //For temporary, should be assigned by Publickey.getKeyType();
    if(KEY_TYPE_RSA == keyType && DIGEST_SHA256 == digestAlg)
      {
        Ptr<const signature::Sha256WithRsa> sigPtr = boost::dynamic_pointer_cast<const signature::Sha256WithRsa> (data.getSignature());
        Name signerName = sigPtr->getKeyLocator ().getKeyName ();
        return m_signerNameRegex.match(signerName);
      }
    
    return false;
  }

  bool 
  IdentityPolicyRule::compare(const Name & dataName, const Name & signerName)
  {
    // _LOG_DEBUG("data namespace: " << dataName.toUri());
    // _LOG_DEBUG("signer namespace: " << signerName.toUri());


    
    if((dataName == signerName) && ("==" == m_op || ">=" == m_op))
      return true;
    
    
    Name::const_iterator i = dataName.begin ();
    Name::const_iterator j = signerName.begin ();

    for (; i != dataName.end () && j != signerName.end (); i++, j++)
      {
	int res = i->compare (*j);
	if (res == 0)
	  continue;
	else
	  return false;
    }
    
    if(i == dataName.end())
      return false;
    else
      return true;
  }

}//security

}//ndn
