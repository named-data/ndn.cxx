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

#include "identity-policy-rule.h"

#include "ndn.cxx/helpers/der/der.h"

#include <boost/filesystem.hpp>
#include <tinyxml.h>
#include <sstream>
#include <fstream>
#include <cryptopp/base64.h>

#include "logging.h"

INIT_LOGGER("ndn.security.BasicPolicyManager");

namespace fs = boost::filesystem;

using namespace std;

namespace ndn
{

namespace security
{
  BasicPolicyManager::BasicPolicyManager(const string & policyPath, Ptr<PrivatekeyStore> privatekeyStore)
    :m_policyPath(policyPath),
     m_policyChanged(false),
     m_policyLoaded(false),
     m_privatekeyStore(privatekeyStore)
  {
    loadPolicy();

    // _LOG_DEBUG("Policy: " << *toXML());
  }

  BasicPolicyManager::~BasicPolicyManager()
  {
    savePolicy();
  }

  void 
  BasicPolicyManager::loadPolicy()
  {
    if(m_policyLoaded)
      return;

    fs::path policyPath(m_policyPath);
    if(!fs::exists(policyPath))
      {
        ostringstream oss;
        oss << time::NowUnixTimestamp().total_seconds();
        string masterKeyName = "local-" + oss.str();
        m_defaultKeyName = masterKeyName;
        m_defaultSym = true;

        m_privatekeyStore->generateKey(masterKeyName);

        return;
      }

    ifstream fs(policyPath.c_str(), ifstream::binary);
    fs.seekg (0, ios::end);
    ifstream::pos_type size = fs.tellg();
    char * memblock = new char [size];
    
    fs.seekg (0, ios::beg);
    fs.read (memblock, size);
    fs.close();

    Blob readData(memblock, size);

    boost::iostreams::stream
      <boost::iostreams::array_source> is (memblock, size);

    Ptr<der::DerSequence> root = DynamicCast<der::DerSequence>(der::DerNode::parse(reinterpret_cast<InputIterator &>(is)));
    const der::DerNodePtrList & children = root->getChildren();
    der::SimpleVisitor simpleVisitor;
    string encryptKeyName = boost::any_cast<string>(children[0]->accept(simpleVisitor));
    bool encryptSym = boost::any_cast<bool>(children[1]->accept(simpleVisitor));
    const Blob& encryptedPolicy = boost::any_cast<const Blob&>(children[2]->accept(simpleVisitor));

    m_defaultKeyName = encryptKeyName;
    m_defaultSym = encryptSym;

    Ptr<Blob> decrypted = m_privatekeyStore->decrypt(encryptKeyName, encryptedPolicy, encryptSym);
    
    string decryptedStr(decrypted->buf(), decrypted->size());
    
    TiXmlDocument xmlDoc;

    xmlDoc.Parse(decrypted->buf());

    delete[] memblock;    

    TiXmlNode * it = xmlDoc.FirstChild();
    
    while(it != NULL)
      {
        if(it->ValueStr() == string("PolicySet"))
          loadPolicySet(dynamic_cast<TiXmlElement *>(it));
        else if(it->ValueStr() == string("TrustAnchors"))
          loadTrustAnchor(dynamic_cast<TiXmlElement *>(it));
        it = it->NextSibling();
      }

    m_policyLoaded = true;
    m_policyChanged = false;
  }

  void 
  BasicPolicyManager::loadPolicySet(TiXmlElement * policySet)
  {
    TiXmlNode * it = policySet->FirstChild();
    while(it != NULL)
      {
        if(it->ValueStr() == string("VerifyPolicies"))
          {
            TiXmlNode * vPolicyRule = it->FirstChild();
            while(vPolicyRule != NULL)
              {
                if(vPolicyRule->ValueStr() == string("IdentityPolicyRule"))
                  setVerificationPolicyRule(IdentityPolicyRule::fromXmlElement(dynamic_cast<TiXmlElement *>(vPolicyRule)));

                vPolicyRule = vPolicyRule->NextSibling();
              }
          }
        else if(it->ValueStr() == string("VerifyExempt"))
          {
            TiXmlNode * vExempt = it->FirstChild();
            while(vExempt != NULL)
              {
                if(vExempt->ValueStr() == string("Regex"))
                  setVerificationExemption(Regex::fromXmlElement(dynamic_cast<TiXmlElement *>(vExempt)));

                vExempt = vExempt->NextSibling();
              }
          }
        else if(it->ValueStr() == string("SignPolicies"))
          {
            TiXmlNode * sPolicyRule = it->FirstChild();
            while(sPolicyRule != NULL)
              {
                if(sPolicyRule->ValueStr() == string("IdentityPolicyRule"))
                  setSigningPolicyRule(IdentityPolicyRule::fromXmlElement(dynamic_cast<TiXmlElement *>(sPolicyRule))); 
 
                sPolicyRule = sPolicyRule->NextSibling();
              }
          }
        else if(it->ValueStr() == string("SignInferences"))
          {
            TiXmlNode * rInfer = it->FirstChild();
            while(rInfer != NULL)
              {
                if(rInfer->ValueStr() == string("Regex"))
                  setSigningInference(Regex::fromXmlElement(dynamic_cast<TiXmlElement *>(rInfer)));

                rInfer = rInfer->NextSibling();
              }
          }
        it = it->NextSibling();
      }
  }

  void
  BasicPolicyManager::loadTrustAnchor(TiXmlElement * trustAnchors)
  {
    TiXmlNode * it = trustAnchors->FirstChild();
    while(it != NULL)
      {
        Blob base64RawCert(it->FirstChild()->ValueStr().c_str(), it->FirstChild()->ValueStr().size());

        string decoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(base64RawCert.buf()), base64RawCert.size(), true,
                                  new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

        Ptr<Blob> rawCertPtr = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
        Certificate cert(*Data::decodeFromWire(rawCertPtr));

        setTrustAnchor(cert);

        it = it->NextSibling();
      }
  }

  void 
  BasicPolicyManager::setDefaultEncryptionKey(const string & keyName, bool sym)
  {
    m_defaultKeyName = keyName;
    m_defaultSym = sym;
  }

  void 
  BasicPolicyManager::savePolicy(const string & keyName, bool sym)
  {
    _LOG_DEBUG("savePolicy");
    if(m_policyChanged)
      {
        string encryptKeyName;
        bool encryptSym;
        if(keyName == string(""))
          {
            if(m_defaultKeyName.empty())
              throw SecException("No key for encryption");
            encryptKeyName = m_defaultKeyName;
            encryptSym = m_defaultSym;
          }
        else
          {
            encryptKeyName = keyName;
            encryptSym = sym;
          }

        ostringstream oss;
        TiXmlDocument * xmlDoc = toXML();
        oss << *xmlDoc;

        Blob preparedData(oss.str().c_str(), oss.str().size());

        Ptr<Blob> encryptedPtr = m_privatekeyStore->encrypt(encryptKeyName, preparedData, encryptSym);
        fs::path policyPath(m_policyPath);
        
        ofstream fs(policyPath.c_str(), ofstream::binary | ofstream::trunc);

        der::DerSequence root;
        Ptr<der::DerPrintableString> savedKeyName = Ptr<der::DerPrintableString>(new der::DerPrintableString(encryptKeyName));
        Ptr<der::DerBool> savedSym = Ptr<der::DerBool>(new der::DerBool(encryptSym));
        Ptr<der::DerOctetString> savedPolicy = Ptr<der::DerOctetString>(new der::DerOctetString(*encryptedPtr));
        root.addChild(savedKeyName);
        root.addChild(savedSym);
        root.addChild(savedPolicy);

        blob_stream blobStream;
        root.encode(reinterpret_cast<OutputIterator &> (blobStream));  
        Ptr<Blob> policyDER = blobStream.buf ();
        
        fs.write(policyDER->buf(), policyDER->size());

        fs.close();
        delete xmlDoc;

        m_policyChanged = false;
      }
  }

  TiXmlDocument * 
  BasicPolicyManager::toXML()
  {
    TiXmlDocument * doc = new TiXmlDocument();

    TiXmlDeclaration * decl = new TiXmlDeclaration("1.0", "", "");  
    doc->LinkEndChild(decl);  

    TiXmlElement * policySet = new TiXmlElement("PolicySet");
    doc->LinkEndChild(policySet);


    TiXmlElement * verifyPolicies = new TiXmlElement("VerifyPolicies");
    policySet->LinkEndChild(verifyPolicies);

    vector< Ptr<PolicyRule> >::iterator vIt = m_verifyPolicies.begin();
    for(; vIt != m_verifyPolicies.end(); vIt++)
      verifyPolicies->LinkEndChild((*vIt)->toXmlElement());

    vector< Ptr<PolicyRule> >::iterator vfIt = m_mustFailVerify.begin();
    for(; vfIt != m_mustFailVerify.end(); vfIt++)
      verifyPolicies->LinkEndChild((*vfIt)->toXmlElement());


    TiXmlElement * verifyExempt = new TiXmlElement("VerifyExempt");
    policySet->LinkEndChild(verifyExempt);
    
    vector< Ptr<Regex> >::iterator eIt = m_verifyExempt.begin();
    for(; eIt != m_verifyExempt.end(); eIt++)
      verifyExempt->LinkEndChild((*eIt)->toXmlElement());


    TiXmlElement * signPolicies = new TiXmlElement("SignPolicies");
    policySet->LinkEndChild(signPolicies);

    vector< Ptr<PolicyRule> >::iterator sIt = m_signPolicies.begin();
    for(; sIt != m_signPolicies.end(); sIt++)
      signPolicies->LinkEndChild((*sIt)->toXmlElement());

    vector< Ptr<PolicyRule> >::iterator sfIt = m_mustFailSign.begin();
    for(; sfIt != m_mustFailSign.end(); sfIt++)
      signPolicies->LinkEndChild((*sfIt)->toXmlElement());
    

    TiXmlElement * signInferences = new TiXmlElement("SignInferences");
    policySet->LinkEndChild(signInferences);
    
    vector< Ptr<Regex> >::iterator rIt = m_signInference.begin();
    for(; rIt != m_signInference.end(); rIt++)
      signInferences->LinkEndChild((*rIt)->toXmlElement());
    
    
    TiXmlElement * trustAnchors = new TiXmlElement("TrustAnchors");
    doc->LinkEndChild(trustAnchors);

    map<Name, Certificate>::iterator tIt = m_trustAnchors.begin();
    for(; tIt != m_trustAnchors.end(); tIt++)
      {
        Ptr<Blob> rawData = tIt->second.encodeToWire();
        string encoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(rawData->buf()), rawData->size(), true,
                                  new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));
        TiXmlElement * trustAnchor = new TiXmlElement("TrustAnchor");
        trustAnchor->LinkEndChild(new TiXmlText(encoded));
        trustAnchors->LinkEndChild(trustAnchor);
      }
    return doc;
  }
  
  void 
  BasicPolicyManager::setSigningPolicyRule (Ptr<PolicyRule> policy)
  {
    if(policy->isPositive())
      m_signPolicies.push_back(policy);
    else
      m_mustFailSign.push_back(policy);
    
    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setSigningInference(Ptr<Regex> inference)
  {
    m_signInference.push_back(inference);
    
    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setVerificationPolicyRule (Ptr<PolicyRule> policy)
  {
    if(policy->isPositive())
      m_verifyPolicies.push_back(policy);
    else
      m_mustFailVerify.push_back(policy);

    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setVerificationExemption (Ptr<Regex> exempt)
  {
    m_verifyExempt.push_back(exempt);

    m_policyChanged = true;
  }

  bool
  BasicPolicyManager::requireVerify (const Data & data)
  {
    vector< Ptr<PolicyRule> >::iterator it = m_verifyPolicies.begin();
    for(; it != m_verifyPolicies.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    it = m_mustFailVerify.begin();
    for(; it != m_mustFailVerify.end(); it++)
      {
	if((*it)->matchDataName(data))
	  return true;
      }

    return false;
  }

  bool 
  BasicPolicyManager::skipVerify (const Data & data)
  {
    vector< Ptr<Regex> >::iterator it = m_verifyExempt.begin();
    for(; it != m_verifyExempt.end(); it++)
      {
	if((*it)->match(data.getName()))
	  return true;
      }

    return false;
  }

  void 
  BasicPolicyManager::setTrustAnchor(const Certificate & certificate)
  {
    m_trustAnchors.insert(pair<const Name, const Certificate>(certificate.getName(), certificate));

    m_policyChanged = true;
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
    vector< Ptr<PolicyRule> >::iterator it = m_mustFailVerify.begin();
    for(; it != m_mustFailVerify.end(); it++)
      {
	if((*it)->satisfy(data))
	  return false;
      }

    it = m_verifyPolicies.begin();
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
    vector< Ptr<PolicyRule> >::iterator it = m_mustFailSign.begin();
    for(; it != m_mustFailSign.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return false;
      }

    it = m_signPolicies.begin();
    for(; it != m_signPolicies.end(); it++)
      {
	if((*it)->satisfy(dataName, certName))
	  return true;
      }

    return false;
  }
  
  Name
  BasicPolicyManager::inferSigningIdentity(const Name & dataName)
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

  Ptr<PolicyRule>
  BasicPolicyManager::parsePolicyRule (const string & policy)
  {
    string cPolicyRule = replaceWS(policy);

    int offset = 0;

    string identityType = getStringItem(cPolicyRule, offset);

    if("IDENTITY_POLICY" == identityType){
      
      if(string::npos == offset) 
	throw SecException("No data regex!");

      string dataRegex = getStringItem(cPolicyRule, offset);


      if(string::npos == offset) 
	throw SecException("No data expand!");

      string dataExpand = getStringItem(cPolicyRule, offset);


      if(string::npos == offset) 
	throw SecException("No relation!");
      
      string op = getStringItem(cPolicyRule, offset);

      
      if(string::npos == offset) 
	throw SecException("No signer regex!");
      
      string signerRegex = getStringItem(cPolicyRule, offset);


      if(string::npos == offset) 
	throw SecException("No signer expand!");
      
      string signerExpand = getStringItem(cPolicyRule, offset);

      
      if(string::npos == offset) 
	throw SecException("No mustSign!");
      
      string isPositiveStr = getStringItem(cPolicyRule, offset);

      bool isPositive = true;
      
      if("NOVERIFY" == isPositiveStr)
	isPositive = false;
      

      return Ptr<PolicyRule>(new IdentityPolicyRule(dataRegex, signerRegex, op, dataExpand, signerExpand, isPositive));
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
