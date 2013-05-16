/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Alexander Afanasyev
 *
 * BSD license, See the COPYING file for more information
 *
 * Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
 */

#ifndef NDN_KEY_H
#define NDN_KEY_H

namespace ndn
{

class Key
{
public:
  Key ();
	// 	self.type = None
	// 	self.publicKeyID = None # SHA256 hash
	// 	# pyccn
	// 	self.ccn_data_dirty = False
	// 	self.ccn_data_public = None  # backing pkey
	// 	self.ccn_data_private = None # backing pkey

  void
  generateRsaKey ();
	// def generateRSA(self, numbits):
	// 	_pyccn.generate_RSA_key(self, numbits)

  void
  privateToDer ();
	// def privateToDER(self):
	// 	if not self.ccn_data_private:
	// 		raise _pyccn.CCNKeyError("Key is not private")
	// 	return _pyccn.DER_write_key(self.ccn_data_private)

  void
  privateToPem ();
	// def privateToPEM(self, filename = None):
	// 	if not self.ccn_data_private:
	// 		raise _pyccn.CCNKeyError("Key is not private")

	// 	if filename:
	// 		f = open(filename, 'w')
	// 		_pyccn.PEM_write_key(self.ccn_data_private, file=f)
	// 		f.close()
	// 	else:
	// 		return _pyccn.PEM_write_key(self.ccn_data_private)

  void
  publicToDer ();
	// def publicToDER(self):
	// 	return _pyccn.DER_write_key(self.ccn_data_public)

  void
  publicToPem ();
  	// def publicToPEM(self, filename = None):
	// 	if filename:
	// 		f = open(filename, 'w')
	// 		_pyccn.PEM_write_key(self.ccn_data_public, file=f)
	// 		f.close()
	// 	else:
	// 		return _pyccn.PEM_write_key(self.ccn_data_public)

  void
  fromDer ();
  	// def fromDER(self, private = None, public = None):
	// 	if private:
	// 		(self.ccn_data_private, self.ccn_data_public, self.publicKeyID) = \
	// 			_pyccn.DER_read_key(private=private)
	// 		return
	// 	if public:
	// 		(self.ccn_data_private, self.ccn_data_public, self.publicKeyID) = \
	// 			_pyccn.DER_read_key(public=public)
	// 		return

  void
  fromPem ();
	// def fromPEM(self, filename = None, private = None, public = None):
	// 	if filename:
	// 		f = open(filename, 'r')
	// 		(self.ccn_data_private, self.ccn_data_public, self.publicKeyID) = \
	// 			_pyccn.PEM_read_key(file=f)
	// 		f.close()
	// 	elif private:
	// 		(self.ccn_data_private, self.ccn_data_public, self.publicKeyID) = \
	// 			_pyccn.PEM_read_key(private=private)
	// 	elif public:
	// 		(self.ccn_data_private, self.ccn_data_public, self.publicKeyID) = \
	// 			_pyccn.PEM_read_key(public=public)

} // ndn

#endif // NDN_KEY_H
