/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Xingyu Ma (maxy12@cs.ucla.edu)
 */

#include <string>

#include "ndn.cxx/security/certificate/publickey.h"
#include <cryptopp/rsa.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/pssr.h>


#include "simplekey-store.h"
using namespace CryptoPP;
using namespace std;

namespace ndn
{
    
    namespace security
    {
        /**
         * @brief generate a pair of asymmetric keys
         * @param keyName the name of the key pair
         * @param keyType the type of the key pair, e.g. RSA
         * @param keySize the size of the key pair
         * @returns true if keys have been successfully generated
         */
        
        /**
         * @brief destructor of PrivateKeyStore
         */
        
		bool
        SimpleKeyStore::generateKeyPair(const string & keyName, KeyType keyType, int keySize)
        {
            if (keyType == KEY_TYPE_RSA) {
                AutoSeededRandomPool rng;
                InvertibleRSAFunction privkey;
                privkey.Initialize(rng, keySize);
                string privateKeyName = SimpleKeyStore::nameTransform(keyName) + "_priv.txt";
                Base64Encoder privkeysink(new FileSink(privateKeyName.c_str()));
                privkey.DEREncode(privkeysink);
                privkeysink.MessageEnd();
                
                RSAFunction pubkey(privkey);
                string publicKeyName = SimpleKeyStore::nameTransform(keyName) + "_pub.txt";
                Base64Encoder pubkeysink(new FileSink( publicKeyName.c_str()));
                pubkey.DEREncode(pubkeysink);
                pubkeysink.MessageEnd();
                return true;
            }
            return false;
        }
        
        Ptr<Publickey>
        SimpleKeyStore::getPublickey(const string & keyName)
        {
            string publicKeyName = SimpleKeyStore::nameTransform(keyName) + "_pub.txt";
            ifstream file (publicKeyName.c_str(), ios::in|ios::binary|ios::ate);
            if (file.is_open())
  					{
                ifstream::pos_type size = file.tellg();
                char * memblock = new char [size];
                file.seekg (0, ios::beg);
                file.read (memblock, size);
                file.close();
                string encoded = string(memblock, size);
                string decoded;
                CryptoPP::StringSource ss2(reinterpret_cast<const unsigned char *>(encoded.c_str()), encoded.size(), true,
                                           new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded)));
			  				Blob b(decoded.c_str(), decoded.size());
                string str("1.2.840.113549.1.1.1");
                OID oid(str);
                delete [] memblock;
                return new Publickey (oid, b);
    				}
            
            return 0;
        }
        
        /**
         * @brief sign data
         * @param keyName the name of the signing key
         * @param digestAlgo the digest algorithm
         * @param pData the pointer to data
         * @returns signature, NULL if signing fails
         */
        Ptr<Blob>
        SimpleKeyStore::sign(const Blob & pData, const string & keyName, DigestAlgorithm digestAlgo)
        {
            AutoSeededRandomPool rng;
            string strContents = string(pData.buf(),pData.size());
            //Read private key
            CryptoPP::ByteQueue bytes;
            string privateKeyName = SimpleKeyStore::nameTransform(keyName) + "_priv.txt";
            FileSource file(privateKeyName.c_str(), true, new Base64Decoder);
            file.TransferTo(bytes);
            bytes.MessageEnd();
            RSA::PrivateKey privateKey;
            privateKey.Load(bytes);
            //Sign message
  				  if (digestAlgo == DIGEST_SHA256)
   				  {
   				  	RSASS<PSS, SHA256>::Signer signer(privateKey);
    		    	size_t length = signer.MaxSignatureLength();
    					SecByteBlock signature(length);
				    	signer.SignMessage(rng, (const byte*) strContents.c_str(),
                       strContents.length(), signature);
                       
            	Ptr<Blob> ret = Ptr<Blob>(new Blob(signature, signature.size()));
            	return ret;
            }
            return 0;
        }
        
        /**
         * @brief decrypt data
         * @param keyName the name of the decrypting key
         * @param pData the pointer to encrypted data
         * @returns decrypted data
         */
        Ptr<Blob>
        SimpleKeyStore::decrypt(const string & keyName, const Blob & pData, bool sym )
        {
            if (!sym)
            {
                AutoSeededRandomPool rng;
                CryptoPP::ByteQueue bytes;
                string privateKeyName = SimpleKeyStore::nameTransform(keyName) + "_priv.txt";
                FileSource file2(privateKeyName.c_str(), true, new Base64Decoder);
                file2.TransferTo(bytes);
                bytes.MessageEnd();
                RSA::PrivateKey privateKey;
                privateKey.Load(bytes);
                
                string recovered;
                
                RSAES_OAEP_SHA_Decryptor d( privateKey );
                
                StringSource( string(pData.buf(), pData.size()), true,
                             new PK_DecryptorFilter( rng, d,
                                                    new StringSink( recovered )
                                                    ) // PK_DecryptorFilter
                             ); // StringSource
                
                Ptr<Blob> ret = Ptr<Blob>(new Blob(recovered.c_str (), recovered.size()));
                return ret;
 						}
 						return 0;
        }
        
        Ptr<Blob>
        SimpleKeyStore::encrypt(const string & keyName, const Blob & pData, bool sym)
        {
            if (!sym)
            {
                AutoSeededRandomPool rng;
                CryptoPP::ByteQueue bytes;
		            string publicKeyName = SimpleKeyStore::nameTransform(keyName) + "_pub.txt";
                FileSource file(publicKeyName.c_str(), true, new Base64Decoder);
                file.TransferTo(bytes);
                bytes.MessageEnd();
                RSA::PublicKey publicKey;
                publicKey.Load(bytes);
                
                string cipher;
                string plain = string(pData.buf(),pData.size());
                RSAES_OAEP_SHA_Encryptor e( publicKey );
                
                StringSource( plain, true,
                             new PK_EncryptorFilter( rng, e,
                                                    new StringSink( cipher )
                                                    )
                             );
                Ptr<Blob> ret = Ptr<Blob>(new Blob(cipher.c_str (), cipher.size()));
                return ret;
            }
            return 0;
        }
        
        
        //TODO Symmetrical key stuff.
        /**
         * @brief generate a symmetric keys
         * @param keyName the name of the key 
         * @param keyType the type of the key, e.g. AES
         * @param keySize the size of the key
         * @returns true if key have been successfully generated
         */
        void 
        SimpleKeyStore::generateKey(const string & keyName, KeyType keyType, int keySize)
        {
            return;
        }
        
        bool
        SimpleKeyStore::doesKeyExist(const string & keyName, KeyClass keyClass)
        {
            return 0;
    	}
    	
        std::string SimpleKeyStore::nameTransform(const string &keyName)
        {
			    std::string digest;
   				CryptoPP::SHA256 hash;  
    			CryptoPP::StringSource foo(keyName, true,
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
					return string(cstr);
        }
        
    } //ndn
    
    
}