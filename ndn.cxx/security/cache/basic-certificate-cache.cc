/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include "basic-certificate-cache.h"

using namespace std;

namespace ndn
{

namespace security
{
  void
  BasicCertificateCache::insertCertificate(Ptr<Certificate> certificate)
  { 
    m_cache.insert(pair<Name, Ptr<Certificate> >(certificate->getName(), certificate));
  }
  
  Ptr<Certificate>
  BasicCertificateCache::getCertificate(const Name & certificateName)
  {
    map<Name, Ptr<Certificate> >::iterator it = m_cache.find(certificateName);

    if(it == m_cache.end())
      {
	return NULL;
      }
    else
      {	
	if(it->second->isTooEarly())
	  return NULL;
	
	if(it->second->isTooLate())
	  {
	    m_cache.erase(it);
	    return NULL;
	  }

	return it->second;
      }
  }
  

}//security

}//ndn

