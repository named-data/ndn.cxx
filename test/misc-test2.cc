#include <boost/test/unit_test.hpp>

#include <iostream>
#include <sstream>
#include <fstream>
#include <tinyxml.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pssr.h>


#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/security/identity/osx-privatekey-store.h"
#include "ndn.cxx/security/identity/simplekey-store.h"
#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/security/certificate/publickey.h"

using namespace std;
using namespace boost::posix_time;
using namespace ndn;
using namespace CryptoPP;
using namespace ndn::security;


BOOST_AUTO_TEST_SUITE(MiscTests2)

BOOST_AUTO_TEST_CASE (hash)
{
    std::string digest;
    
    CryptoPP::SHA256 hash;  
    CryptoPP::StringSource foo("/ndn/xingyu", true,
                               new CryptoPP::HashFilter(hash,
                                                        new CryptoPP::Base64Encoder (new CryptoPP::StringSink(digest))));
    
    char * cstr = new char [digest.length()+1];
    std::strcpy (cstr, digest.c_str());
    
    for (int i = 0; i < digest.length(); i++)
    {
        if (cstr[i] == '/')
        {
            cstr[i] = '%';
        }
    }
    std::cout<<string(cstr)<<std::endl;
    std::cout << digest << std::endl;
}

BOOST_AUTO_TEST_CASE (GenKey)
{
	SimpleKeyStore sp;
	sp.generateKeyPair("/ndn/xingyu");

}


BOOST_AUTO_TEST_CASE (Read)
{
		SimpleKeyStore sp;
	Ptr<Publickey>  p = sp.getPublickey("/ndn/xingyu");
//	cout<<"hrer"<<endl;
	Blob b = p->getKeyBlob();
	cout<<string(b.buf(),b.size())<<endl;
//	readCert("_xingyu_pub.txt");
	
}

BOOST_AUTO_TEST_CASE (Sign)
{
	SimpleKeyStore sp;
	string str1("1234567");
  Blob blob1(str1.c_str(), str1.size());
  
  Ptr<Blob> sig = sp.sign(blob1,"/ndn/xingyu");
	cout<<string(sig->buf(),sig->size())<<endl;
	
   //Read public key
  CryptoPP::ByteQueue bytes;
    string publicKeyName = sp.nameTransform("/ndn/xingyu") + "_pub.txt";
  FileSource file(publicKeyName.c_str(), true, new Base64Decoder);
  file.TransferTo(bytes);
  bytes.MessageEnd();
  RSA::PublicKey pubKey;
  pubKey.Load(bytes);
   
  RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);

  string combined(str1);
  combined.append(string(sig->buf(),sig->size()));

   //Verify signature
  try
  {
       StringSource(combined, true,
           new SignatureVerificationFilter(
               verifier, NULL,
               SignatureVerificationFilter::THROW_EXCEPTION
          )
       );
       cout << "Signature OK" << endl;
  }
  catch(SignatureVerificationFilter::SignatureVerificationFailed &err)
  {
       cout << err.what() << endl;
  }

}

BOOST_AUTO_TEST_CASE (VerifySign)
{
    AutoSeededRandomPool rng;
 	SimpleKeyStore sp;   
    InvertibleRSAFunction parameters;
    parameters.GenerateRandomWithKeySize(rng, 1536);
    
    RSA::PrivateKey privateKey(parameters);
    RSA::PublicKey publicKey(parameters);
    
    // Message
    string message = "gigi gaga.";
    Blob blob1(message.c_str(), message.size());
    // Signer object
 /*   RSASS<PSS, SHA256>::Signer signer(privateKey);
    
    // Create signature space
    size_t length = signer.MaxSignatureLength();
    SecByteBlock signature(length);
    
    // Sign message
    signer.SignMessage(rng, (const byte*) message.c_str(),
                       message.length(), signature);
   */ 
    // Verifier object
    CryptoPP::ByteQueue bytes;
    string publicKeyName = sp.nameTransform("/ndn/xingyu") + "_pub.txt";
    //    std::string pub = sp.nameTransform("/ndn/xingyu");
    //    cout<<pub<<endl;
    FileSource file(publicKeyName.c_str(), true, new Base64Decoder);
    //  FileSource file("pubkey.txt", true, new Base64Decoder);
    file.TransferTo(bytes);
    bytes.MessageEnd();
    RSA::PublicKey pubKey;
    pubKey.Load(bytes);
    
    RSASS<PSS, SHA256>::Verifier verifier(pubKey);
    
    Ptr<Blob> sig = sp.sign(blob1,"/ndn/xingyu");
    string signature = string(sig->buf(),sig->size());
    cout<<signature<<endl;
    // Verify
    bool result = verifier.VerifyMessage((const byte*)message.c_str(),
                                         message.length(), (const byte*) signature.c_str(), signature.size());
    
    // Result
    if(true == result) {
        cout << "Signature on message verified" << endl;
    } else {
        cout << "Message verification failed" << endl;
    }
}


BOOST_AUTO_TEST_CASE (Encrypt)
{
			SimpleKeyStore sp,sp2;
			string str1("RSA Encryption");
 			Blob blob1(str1.c_str(), str1.size());
			Ptr<Blob> enc = sp.encrypt("/ndn/xingyu", blob1);
			cout<<string(enc->buf(),enc->size())<<endl;
			Blob cipher(enc->buf(),enc->size());
		  Ptr<Blob> rec = sp2.decrypt("/ndn/xingyu",cipher);
		  cout<<string(rec->buf(),rec->size())<<endl;
}



BOOST_AUTO_TEST_SUITE_END()
