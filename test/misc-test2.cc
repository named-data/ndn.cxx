#include <boost/test/unit_test.hpp>

#include <iostream>
#include <sstream>
#include <fstream>
#include <tinyxml.h>
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/sha.h>
#include <cryptopp/pssr.h>
#include <cryptopp/modes.h>

#include <boost/date_time/posix_time/posix_time.hpp>

#include "ndn.cxx/security/identity/osx-privatekey-storage.h"
#include "ndn.cxx/security/identity/simplekey-store.h"
#include "ndn.cxx/security/certificate/certificate-data.h"
#include "ndn.cxx/security/certificate/publickey.h"

using namespace std;
using namespace boost::posix_time;
using namespace ndn;
using namespace CryptoPP;
using namespace ndn::security;


BOOST_AUTO_TEST_SUITE(MiscTests2)

BOOST_AUTO_TEST_CASE (MKDIR)
{
    SimpleKeyStore sp(".//keystore//");
    sp.generateKeyPair(ndn::Name("/ndn/xingyu"));
}
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
    SimpleKeyStore sp(".//keystore//");
    sp.generateKeyPair(ndn::Name("/ndn/maxingyu"));

}


BOOST_AUTO_TEST_CASE (Read)
{
		SimpleKeyStore sp;
		Ptr<Publickey>  p = sp.getPublickey(ndn::Name("/ndn/xingyu"));
//	cout<<"hrer"<<endl;
	Blob b = p->getKeyBlob();
	cout<<string(b.buf(),b.size())<<endl;
//	readCert("_xingyu_pub.txt");
	
}
BOOST_AUTO_TEST_CASE (ReadKey)
{
    ifstream file ("_sym.txt", ios::in|ios::binary|ios::ate);
    if (file.is_open())
    {
        ifstream::pos_type size = file.tellg();
        char * memblock = new char [size];
        file.seekg (0, ios::beg);
        file.read (memblock, size);
        file.close();
        cout<<string(memblock,size)<<endl;
        string decoded;
  			CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(memblock), size, true,
			    new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
        cout<<decoded<<endl;
        
       cout <<reinterpret_cast<const unsigned char *>(decoded.c_str())<<endl;
//        cout<<bytes<<endl;
        delete []memblock;
       
//        cout << "key: " << encoded << endl;
    }
}

BOOST_AUTO_TEST_CASE (WriteKey)
{
	  ofstream file ("_sym.txt", ios::out|ios::binary|ios::ate);
    if (file.is_open())
    {
    	string dd = "dsfasfsaf";
    	file.write(dd.c_str(), dd.size());
    	file.close();
  	}
}

BOOST_AUTO_TEST_CASE (Sign)
{
    SimpleKeyStore sp(".//keystore//");
	string str1("1234567");
  Blob blob1(str1.c_str(), str1.size());
  
  Ptr<Blob> sig = sp.sign(blob1,ndn::Name("/ndn/xingyu"));
	cout<<string(sig->buf(),sig->size())<<endl;
	
   //Read public key
  CryptoPP::ByteQueue bytes;
  string publicKeyName = sp.nameTransform("/ndn/xingyu") + "_pub.txt";
  cout<<publicKeyName<<endl;
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
    
    Ptr<Blob> sig = sp.sign(blob1,ndn::Name("/ndn/xingyu"));
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
            SimpleKeyStore sp(".//keystore//");
            SimpleKeyStore sp2(".//keystore//");
			string str1("RSA Encryption 123456789");
 			Blob blob1(str1.c_str(), str1.size());
			Ptr<Blob> enc = sp.encrypt(ndn::Name("/ndn/xingyu"), blob1);
//			cout<<string(enc->buf(),enc->size())<<endl;
			Blob cipher(enc->buf(),enc->size());
			Ptr<Blob> rec = sp2.decrypt(ndn::Name("/ndn/xingyu"),cipher);
		  cout<<string(rec->buf(),rec->size())<<endl;
}


BOOST_AUTO_TEST_CASE (AES)
{
    using CryptoPP::AES;
    AutoSeededRandomPool rnd;
    
    // Generate a random key
//    cout<< AES::DEFAULT_KEYLENGTH <<endl;
    SecByteBlock key(0x00, 256);
    rnd.GenerateBlock( key, key.size() );
    
    Ptr<Blob> ret = Ptr<Blob>(new Blob(key, key.size()));
    cout<<endl;
    cout<<string(string(ret->buf(),ret->size()))<<endl;
    // Generate a random IV
    byte iv[AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, AES::BLOCKSIZE);
    
	  string plain = "ADF Mode Test";
	  string cipher, encoded, recovered;
    
    encoded.clear();
	  StringSource(key, key.size(), true,
                 new HexEncoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
	  cout << "key: " << encoded << endl;
 //   unsigned char *key2 = new unsigned char [encoded.length()+1];
 //   std::strcpy (key2, encoded.c_str());
//    unsigned char key2[encoded.size()] = reinterpret_cast<const unsigned char *>(encoded.c_str());
    
    
    
    string decoded;
    CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(encoded.c_str()), encoded.size(), true,
		new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
        cout<<"here  "<<decoded<<endl;
/*    //////////////////////////////////////////////////////////////////////////
    // Encrypt
    
    CFB_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
    cfbEncryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);
    
    //////////////////////////////////////////////////////////////////////////
    // Decrypt
    
    CFB_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
    cfbDecryption.ProcessData((byte*)plainText, (byte*)plainText, messageLen);
 */
    
/*    string cipher;
    StringSink* sink = new StringSink(cipher);
    Base64Encoder* base64_enc = new Base64Encoder(sink);
    CBC_Mode<AES>::Encryption aes(key, sizeof(key), iv);
    StreamTransformationFilter* aes_enc = new StreamTransformationFilter(aes, base64_enc);
    StringSource source(plainText, true, aes_enc);
 */
    try
	{
		cout << "plain text: " << plain << endl;
        
		CFB_Mode< AES >::Encryption e;
		e.SetKeyWithIV(reinterpret_cast<const unsigned char *>(decoded.c_str()), sizeof(decoded.c_str()), iv);
        
		// CFB mode must not use padding. Specifying
		//  a scheme will result in an exception
		StringSource(plain, true,
                     new StreamTransformationFilter(e,
                                                    new StringSink(cipher)
                                                    ) // StreamTransformationFilter
                     ); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
 	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
                 new Base64Encoder(
                                new StringSink(encoded)
                                ) // HexEncoder
                 ); // StringSource
    cout << "cipher text: " << encoded << endl;
  
//    cout<<"  dfa: "<<key<<endl;
	/*********************************\
     \*********************************/
    
	try
	{
		CFB_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);
        
		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true,
                       new StreamTransformationFilter(d,
                       new StringSink(recovered)
                       ) // StreamTransformationFilter
     ); // StringSource
        
		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
//    cout<<cipher<<endl;
}

BOOST_AUTO_TEST_CASE (SYM_GEN)
{
    SimpleKeyStore sp(".//keystore//");
    sp.generateKey(ndn::Name("/ndn/xingyuma"));
}

BOOST_AUTO_TEST_CASE (SYM_EN)
{
        SimpleKeyStore sp(".//keystore//");
        SimpleKeyStore sp2(".//keystore//");
			string str1("SYM Encryption dudi");
 			Blob blob1(str1.c_str(), str1.size());
			Ptr<Blob> enc = sp.encrypt(ndn::Name("/ndn/xingyu"), blob1,false);
			Blob cipher(enc->buf(),enc->size());
			Ptr<Blob> rec = sp2.decrypt(ndn::Name("/ndn/xingyu"),cipher,false);
		  cout<<"recover:  "<<string(rec->buf(),rec->size())<<endl;
}


BOOST_AUTO_TEST_SUITE_END()
