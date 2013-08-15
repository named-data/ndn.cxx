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
#include "ndn.cxx/security/encoding/der.h"

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
      return;

    ifstream fs(policyPath.c_str(), ifstream::binary);
    fs.seekg (0, ios::end);
    ifstream::pos_type size = fs.tellg();
    char * memblock = new char [size];
    
    fs.seekg (0, ios::beg);
    fs.read (memblock, size);
    fs.close();

    Blob readData(memblock, size);
    _LOG_DEBUG("Size: " << size);
    _LOG_DEBUG("READ Data");

    DERendec decoder;

    Ptr<vector<Ptr<Blob> > > derItemListPtr = decoder.decodeSequenceDER(readData);
    string encryptKeyName = *decoder.decodePrintableStringDER(*derItemListPtr->at(0));
    bool encryptSym = decoder.decodeBoolDER(*derItemListPtr->at(1));
    Ptr<Blob> encryptedPolicy = decoder.decodeStringDER(*derItemListPtr->at(2));

    m_defaultKeyName = encryptKeyName;
    m_sym = encryptSym;

    Ptr<Blob> decrypted = m_privatekeyStore->decrypt(encryptKeyName, *encryptedPolicy, encryptSym);
    
    string decryptedStr(decrypted->buf(), decrypted->size());
    
    TiXmlDocument xmlDoc;

    xmlDoc.Parse(decrypted->buf());

    delete[] memblock;    

    TiXmlNode * it = xmlDoc.FirstChild();
    
    while(it != NULL)
      {
        _LOG_DEBUG(" " << it->ValueStr());
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
            TiXmlNode * vPolicy = it->FirstChild();
            while(vPolicy != NULL)
              {
                if(vPolicy->ValueStr() == string("IdentityPolicy"))
                  {
                    Ptr<IdentityPolicy> p = IdentityPolicy::fromXmlElement(dynamic_cast<TiXmlElement *>(vPolicy));
                    if(p->mustVerify())
                      m_verifyPolicies.push_back(p);
                    else
                      m_notVerifyPolicies.push_back(p);
                  }
                vPolicy = vPolicy->NextSibling();
              }
          }
        else if(it->ValueStr() == string("SignPolicies"))
          {
            TiXmlNode * sPolicy = it->FirstChild();
            while(sPolicy != NULL)
              {
                if(sPolicy->ValueStr() == string("IdentityPolicy"))
                  {
                    Ptr<IdentityPolicy> p = IdentityPolicy::fromXmlElement(dynamic_cast<TiXmlElement *>(sPolicy));                    
                    m_signPolicies.push_back(p);
                  }
                sPolicy = sPolicy->NextSibling();
              }
          }
        else if(it->ValueStr() == string("SignInferences"))
          {
            TiXmlNode * rInfer = it->FirstChild();
            while(rInfer != NULL)
              {
                if(rInfer->ValueStr() == string("Regex"))
                  {
                    Ptr<Regex> r = Regex::fromXmlElement(dynamic_cast<TiXmlElement *>(rInfer));
                    m_signInference.push_back(r);
                  }
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
        _LOG_DEBUG("cert: " << it->FirstChild()->ValueStr());
        string decoded;
        CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(base64RawCert.buf()), base64RawCert.size(), true,
                                  new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

        Ptr<Blob> rawCertPtr = Ptr<Blob>(new Blob(decoded.c_str(), decoded.size()));
        Certificate cert(*Data::decodeFromWire(rawCertPtr));
        _LOG_DEBUG("cert is ready!");
        setTrustAnchor(cert);

        it = it->NextSibling();
      }
  }

  void 
  BasicPolicyManager::setDefaultEncryptionKey(const string & keyName, bool sym)
  {
    m_defaultKeyName = keyName;
    m_sym = sym;
  }

  void 
  BasicPolicyManager::savePolicy(const string & keyName, bool sym)
  {
    if(m_policyChanged)
      {
        _LOG_DEBUG("I was here!");
        string encryptKeyName;
        bool encryptSym;
        if(keyName == string(""))
          {
            if(m_defaultKeyName.empty())
              throw SecException("No key for encryption");
            encryptKeyName = m_defaultKeyName;
            encryptSym = m_sym;
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

        DERendec encoder;
        
        vector<Ptr<Blob> > derItemList;
        derItemList.push_back(encoder.encodePrintableStringDER(encryptKeyName));
        derItemList.push_back(encoder.encodeBoolDER(encryptSym));
        derItemList.push_back(encoder.encodeStringDER(*encryptedPtr));
        Ptr<Blob> derBlobPtr = encoder.encodeSequenceDER(derItemList);
        
        fs.write(derBlobPtr->buf(), derBlobPtr->size());

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

    vector< Ptr<Policy> >::iterator vIt = m_verifyPolicies.begin();
    for(; vIt != m_verifyPolicies.end(); vIt++)
      verifyPolicies->LinkEndChild((*vIt)->toXmlElement());

    vector< Ptr<Policy> >::iterator vnIt = m_notVerifyPolicies.begin();
    for(; vnIt != m_notVerifyPolicies.end(); vnIt++)
      verifyPolicies->LinkEndChild((*vnIt)->toXmlElement());


    TiXmlElement * signPolicies = new TiXmlElement("SignPolicies");
    policySet->LinkEndChild(signPolicies);

    vector< Ptr<Policy> >::iterator sIt = m_signPolicies.begin();
    for(; sIt != m_signPolicies.end(); sIt++)
      signPolicies->LinkEndChild((*sIt)->toXmlElement());
    

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
  BasicPolicyManager::setSigningPolicy (const string & policyStr)
  {
    Ptr<Policy> policy = parsePolicy(policyStr);
    m_signPolicies.push_back(policy);
    
    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setSigningPolicy (Ptr<Policy> policy)
  {
    m_signPolicies.push_back(policy);
    
    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setSigningInference(const string & inferenceStr)
  {
    Ptr<Regex> inference = parseInference(inferenceStr);
    m_signInference.push_back(inference);
    
    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setSigningInference(Ptr<Regex> inference)
  {
    m_signInference.push_back(inference);
    
    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setVerificationPolicy (const string & policyStr)
  {
    Ptr<Policy> policy = parsePolicy(policyStr);
    if(policy->mustVerify())
      m_verifyPolicies.push_back(policy);
    else
      m_notVerifyPolicies.push_back(policy);

    m_policyChanged = true;
  }

  void 
  BasicPolicyManager::setVerificationPolicy (Ptr<Policy> policy)
  {
    if(policy->mustVerify())
      m_verifyPolicies.push_back(policy);
    else
      m_notVerifyPolicies.push_back(policy);

    m_policyChanged = true;
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
