#include <boost/test/unit_test.hpp>

#include <iostream>
#include <sstream>
#include <fstream>
#include <tinyxml.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/security/identity/osx-privatekey-store.h"
#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/security/certificate/publickey.h"
#include "ndn.cxx/security/encoding/der.h"

using namespace std;
using namespace boost::posix_time;
using namespace ndn;

BOOST_AUTO_TEST_SUITE(MiscTests)

Ptr<Blob> readKey(string filename)
{
  ifstream file (filename.c_str(), ios::in|ios::binary|ios::ate);

  if (file.is_open())
  {
    ifstream::pos_type size = file.tellg();
    char * memblock = new char [size];

    file.seekg (0, ios::beg);
    file.read (memblock, size);
    file.close();

    Ptr<Blob> cert = Ptr<Blob>::Create();
    
    cert->insert(cert->end(), memblock, memblock + size);

    delete[] memblock;

    return cert;
  }
  else cout << "Unable to open file";

  return 0;
}


void showDER(Ptr<Blob> p)
{
  Blob::iterator it = p->begin();
  for(; it < p->end(); it++){
    cout << " " << hex << setw(2) << setfill('0') << (unsigned int) ((unsigned char) *it);
  }
  cout << endl;

}

Ptr<Blob> readCert(string filename)
{
  ifstream file (filename.c_str(), ios::in|ios::binary|ios::ate);

  if (file.is_open())
  {
    ifstream::pos_type size = file.tellg();
    char * memblock = new char [size];

    file.seekg (0, ios::beg);
    file.read (memblock, size);
    file.close();

    Ptr<Blob> cert = Ptr<Blob>::Create();
    
    cert->insert(cert->end(), memblock, memblock + size);

    delete[] memblock;

    return cert;
  }
  else cout << "Unable to open file";

  return 0;
}

BOOST_AUTO_TEST_CASE (Time)
{
  ptime time = second_clock::universal_time();
  string str = to_iso_string(time);
  int index = str.find_first_of('T');
  cout << str.substr(0, index) + str.substr(index+1, str.size() - index -1) << endl;

  ptime ts1(pos_infin);
  ptime ts2(boost::gregorian::date (1970, boost::gregorian::Jan, 1));
  cout << to_iso_string(ts2 + seconds(315360000)) << endl;
}

BOOST_AUTO_TEST_CASE (TinyXML)
{
  TiXmlDocument doc;  
  TiXmlElement* msg;
  // TiXmlDeclaration* decl = new TiXmlDeclaration( "1.0", "", "" );  
  // doc.LinkEndChild( decl );  
 
  TiXmlElement * root = new TiXmlElement( "MyApp" );  
  doc.LinkEndChild( root );  
  
  TiXmlComment * comment = new TiXmlComment();
  comment->SetValue(" Settings for MyApp " );  
  root->LinkEndChild( comment );  
 
  TiXmlElement * msgs = new TiXmlElement( "Messages" );  
  root->LinkEndChild( msgs );  
  
  msg = new TiXmlElement( "Welcome" );  
  msg->LinkEndChild( new TiXmlText( "Welcome to MyApp" ));  
  msgs->LinkEndChild( msg );  
  cout << *msg << endl;
  
  msg = new TiXmlElement( "Farewell" );  
  msg->LinkEndChild( new TiXmlText( "Thank you for using MyApp" ));  
  msgs->LinkEndChild( msg );  
  
  ostringstream oss;
  oss << doc;
  cout << oss.str() << endl;
  
  TiXmlDocument newDoc;
  newDoc.Parse(oss.str().c_str());
  cout << newDoc << endl;
}

BOOST_AUTO_TEST_CASE (Base64)
{
  string str = "abcdefg";
  
  string encoded;
  CryptoPP::StringSource ss(reinterpret_cast<const unsigned char *>(str.c_str()), str.size(), true,
			    new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), false));

  cout << encoded << endl;

  string decoded;
  CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(encoded.c_str()), encoded.size(), true,
			    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));

  cout << decoded << endl;
}

BOOST_AUTO_TEST_CASE (IO)
{
}

BOOST_AUTO_TEST_CASE (Crypto)
{
  // CryptoPP::RSA::PublicKey pubKey;

  // CryptoPP::ByteQueue queue;

  // CryptoPP::FileSource file("out1.pub", true);
  // file.TransferTo(queue);
  // queue.MessageEnd();

  // pubKey.Load(queue);

  // RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);
  
  // string data = "testDataTestData";
  // char * sig = new char[256];
  // ifstream sigStream("sig.sig");
  // sigStream.read(sig, 256);
  // string sigs(sig, 256);

  
  // StringSource(data+sigs, 
  // 	       true,
  // 	       new SignatureVerificationFilter(verifier, 
  // 					       NULL,
  // 					       SignatureVerificationFilter::THROW_EXCEPTION
  // 					       ) // SignatureVerificationFilter
  // 	       ); // StringSource

  // delete sig;
  
}

BOOST_AUTO_TEST_CASE (DER)
{
  // security::DERendec endec;

  // // showDER(endec.EncodeIntegerDER(-1));
  // // showDER(endec.EncodeIntegerDER(0));
  // // showDER(endec.EncodeIntegerDER(1));
  // // showDER(endec.EncodeIntegerDER(127));
  // // showDER(endec.EncodeIntegerDER(128));
  // // showDER(endec.EncodeIntegerDER(256));
  // // showDER(endec.EncodeIntegerDER(2147483647));
  // // showDER(endec.EncodeIntegerDER(-2147483648));
  // // showDER(endec.EncodeIntegerDER(-128));
  // // showDER(endec.EncodeIntegerDER(-129));

  // showDER(endec.EncodePrintableStringDER("1234567890"));
  
  // showDER(endec.EncodeOidDER("1.2.840.113549.1"));

  // showDER(endec.EncodeGTimeDER("20130720010203Z"));

  // vector<Ptr<Blob> > seq;
  // // seq.push_back(endec.EncodeIntegerDER(1));
  // // seq.push_back(endec.EncodeStringDER("1"));
  // seq.push_back(endec.EncodeOidDER("1.2.840.113549.1"));
  // seq.push_back(endec.EncodeGTimeDER("20130720010203Z"));
  
  // showDER(endec.EncodeSequenceDER(seq));

  // // int offset = 0;
  // // cout << "Decode 1234567890: " << endec.DecodeStringDER(endec.EncodeStringDER("1234567890"), offset)->c_str() << endl;
  // // offset = 0;
  // // cout << "Decode ptime: " << to_iso_string(*endec.DecodeGTimeDER(endec.EncodeGTimeDER(second_clock::universal_time()), offset)) << endl;
  // // offset = 0;
  // // Ptr<vector<int> > oidPtr = endec.DecodeOidDER(endec.EncodeOidDER(oid), offset);
  // // cout << "Decode oid: " << oidPtr->size() << " " << oidPtr->at(4) << endl;

  // endec.PrintDecoded(readCert("out1.pub"), "", 0);

  // Ptr<vector<int> > oidPtr = endec.StringToOid("1.2.3.4.5");
  // cout << oidPtr->size() << " " << endec.OidToString(*oidPtr) << endl;

}

BOOST_AUTO_TEST_CASE (Endianness)
{
  uint32_t i = 1;
  char * p = (char *)&i;
  cout << hex << (int)p[0] << endl;
  cout << hex << (int)p[3] << endl;
  cout << boolalpha << (1 == *(char *)&i) << endl;
}

BOOST_AUTO_TEST_CASE (Digest)
{
  char s[] = "abcd";
  Blob blob(s, 4);

  Ptr<Blob> keyPtr = readKey("out1.pub");

  security::Publickey pubKey(*keyPtr, false);

  Ptr<Blob> digest = pubKey.getDigest();

  security::DERendec endec;
  endec.printBlob(*digest, "");
}

BOOST_AUTO_TEST_CASE (BlobComparison)
{
  string str1("1234567");
  string str2("abcdefg");

  Blob blob1(str1.c_str(), str1.size());
  Blob blob2(str2.c_str(), str2.size());
  Blob blob3(str1.c_str(), str1.size());
  
  cout << boolalpha << (blob1 == blob2) << endl;
  cout << boolalpha << (blob3 == blob2) << endl;
  cout << boolalpha << (blob1 == blob3) << endl;


}

BOOST_AUTO_TEST_CASE (SignVerify)
{
  // RSA::PublicKey pubKey;

  // ByteQueue queue;

  // FileSource file("out1.pub", true);
  // file.TransferTo(queue);
  // queue.MessageEnd();

  // pubKey.Load(queue);

  // RSASSA_PKCS1v15_SHA_Verifier verifier(pubKey);
  
  // string data = "testDataTestData";
  // char * sig = new char[256];
  // ifstream sigStream("sig.sig");
  // sigStream.read(sig, 256);
  // string sigs(sig, 256);

  
  // StringSource(data+sigs, 
  // 	       true,
  // 	       new SignatureVerificationFilter(verifier, 
  // 					       NULL,
  // 					       SignatureVerificationFilter::THROW_EXCEPTION
  // 					       ) // SignatureVerificationFilter
  // 	       ); // StringSource

  // delete sig;
  
  using namespace CryptoPP;

  security::OSXPrivatekeyStore keystore;
  string keyName = "/ndn/ucla/yingdi";
  string testData = "testDataTestData";

  Ptr<security::Publickey> publickeyPtr = keystore.getPublickey(keyName);

  Ptr<Blob> pTestData = Ptr<Blob>(new Blob(testData.c_str(), testData.size()));

  RSA::PublicKey pubKey;
  // ByteQueue queue;
  // FileSource file("out1.pub", true);
  // file.TransferTo(queue);
  // queue.MessageEnd();
  // pubKey.Load(queue);
  ByteQueue queue;
  queue.Put((const byte*)publickeyPtr->getKeyBlob ()->buf (), publickeyPtr->getKeyBlob ()->size ());
  pubKey.Load(queue);


  try{
    Ptr<Blob> pSig = keystore.sign(*pTestData, keyName, security::DIGEST_SHA256);
    string sigs(pSig->buf(), pSig->size());

    RSASS<PKCS1v15, SHA256>::Signer signer;

    string cppsig;

    // StringSource(testData, 
    // 		 true, 
    // 		 new SignerFilter(NullRNG(), signer,
    // 				  new StringSink(cppsig)
    // 				  ) // SignerFilter
    // 		 ); // StringSource


    RSASS<PKCS1v15, SHA256>::Verifier verifier (pubKey);
    bool result = verifier.VerifyMessage((const byte*) testData.c_str(), testData.length(), (const byte*)pSig->buf(), pSig->size());

    cout << boolalpha << result << endl;
    // StringSource(testData+sigs, 
    // 		 true,
    // 		 new SignatureVerificationFilter(verifier, 
    // 						 NULL,
    // 						 SignatureVerificationFilter::THROW_EXCEPTION
    // 						 ) // SignatureVerificationFilter
    // 		 ); // StringSource
  }catch (security::SecException & e){
    cerr << e.Msg() << endl;
  }



}

BOOST_AUTO_TEST_SUITE_END()
