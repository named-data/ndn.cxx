#!/usr/bin/env python
import requests
import json
import os,sys,getopt
import urllib
import argparse
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto import Random

_start = "";
_end = "";
_sign_id = "";
_inst_id = "";

def base64Change(_str):
        s = "";
        for i in range(len(_str)):
                if (_str[i] == '/'):
                        s += '~';
                else:
                        s += _str[i];
        return s;


def transform(_str):
	s = "";
	for i in range(len(_str)):
		if (_str[i] == '\''):
			s += '\"';
			continue;
		if ((_str[i] == 'u' and (_str[i-1] == ' ' or _str[i-1] == '{'))):
			s += '';
		else:
		  s += _str[i];
	return s;
	
def get_info(_str,_info):
	_it = _str.split(",");
	for i in range(len(_it)):
		_tmp = _it[i].split(":");
		if (_tmp[0].find(_info) > 0):
			_ret = _tmp[1].split('\'');
			return _ret[1];
		else:
			continue;

def nameTransform(_str):
	_arr = _str.split('/');
	_ret = "";
	for i in range(1,len(_arr)):
		_ret += _arr[i];
		_ret += "-";
	return _ret[0:len(_ret)-1];


def denial(_input):
	_keyname = get_info(_input,"ndn-name");
        _s = "./opt-tool nack " + _keyname + "  "+ _sign_id;
	os.system(_s);

def issue(_input):
	_key =  get_info(_input,"key");
	_email = get_info(_input,"email");
	_key = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Dk6cCbjzHJbFCxxlGDCvsgrxEIOB3tXrmoNsjiCAuxiA7UGV3m6HGMU3trc0mGC4SQK3IQYOSIP7IiUOQA/mbabo6obvYIKfFi4PA2sNECghiIvGCKErJZUNXhyoQhCCYe2M9IAkK6DdcAKiHMUIIKKxA2XOT7GNQ0VEOc8D5bmIAH9TvtfCwGsY5vmuxoioU+EfwWvOa8rIwP4KgeyG7HJ4/4/DlCjdMLn278qzEZLugrqUjGBZzUuqe6Z8695lbFGFehdvY4FqMT9zxXSxzbRk4wuD9XHtF3J/c6lktAis4MZsSWoGZWyiGEIb5lyTntMVtUP2JZ6aBfgQBvQ7wIDAQAB";
	_keyname = get_info(_input,"ndn-name");
        print "Input start time (in YYYYMMDDhhmmss)";
        _start =  sys.stdin.readline().strip('\n');
        print "Input end time (in YYYYMMDDhhmmss)";
        _end =  sys.stdin.readline().strip('\n');
        _given_name = "aa";
        _surname = "bb";
        _org_name = "ucla";
        _email = "maxy12@cs.ucla.edu"
        _group_name = "irl";
        _advisor_name = "lixia zhang";
        _subject = " 2.5.4.11 "+ _org_name + " 2.5.4.10 "+ _group_name + " 2.5.4.42 "+_given_name + " 2.5.4.4 "+ _surname + " 1.2.840.113549.1.9.1 " + _email + "2.5.4.80" + _advisor_name ;
        print _subject

	_s = "./ndn-certgen-opt -n " +_keyname+ " -S "+_start +" -E " + _end + " -N " + _subject + " -k " +_key+" -s " + _sign_id;
#	print _s;
	os.system(_s);
	list = os.listdir(".");
	array = "";
	_keyname_tran = nameTransform(_keyname);
	print _keyname_tran
	for line in list:
		if (line.find(_keyname_tran)>=0):
			ins = open( line, "r" );
			for tt in ins:
				if (tt.find("---")==0):
					continue;
				array += tt[0:len(tt)-1];
#                        array = urllib.quote_plus(array);
                        array = array.encode('hex')
			_s = "curl -i http://cert.ndn.ucla.edu:5000/ndn/auth/v1.1/candidates/"+_email +"/addcert/"+array;
			print _s;
#			subprocess.call(['curl','-i',_s]);
                        os.system(_s);
#			r = requests.post(_s, auth=('user', 'pass'));
			break;

def configuration(_cert,_inst_id):
	query = 'http://cert.ndn.ucla.edu:5000/ndn/auth/v1.1/candidates/'+_inst_id;
	command = "./opt-tool sign " + query;
        command += "  ";
        command += _sign_id;
        print command
        list = os.popen(command).read();
        query = query + list;
        print query
	r = requests.get(query, auth=('user', 'pass')) 
	_it = r.text.split('<br/>');
        
        if (len(_it) >= 1):
                for i in range(0, len(_it)-1):
                        each = _it[i];
                        _name = get_info(each,"ndn-name");
                        _out_info = "Do you want to give certificate to "+_name;
                        _out_info += "(yes/no)?";
                        print _out_info
                        line = sys.stdin.readline();
                        if (line == "yes\n"):
                                issue(each);
                        else:
                                denial(each);
#                                print 'no certificate issued to' + _name

def configure_cert(cert_name):
        _s = "./ndn-install-cert -f " + cert_name + " -K -I";
        print _s
	os.system(_s);

if __name__ == "__main__":
 #       _inst_id = ''
#        _sign_id = '' #only sign pub key prefix
        _configure_file = ''
        _args = sys.argv[1:];
        for i in range(0,len(_args)):
                if (_args[i] == '-h'):
                        print "help info";
                        sys.exit(0);
                if (_args[i] == '-c'):
                        configure_cert(_args[i+1]);
                        sys.exit(0);
#                        _cert_file = _args[i+1];
                if (_args[i] == '-i'):
                        _inst_id = _args[i+1];
                if (_args[i] == '-s'):
                        _sign_id = _args[i+1];
                if (_args[i] == '-f'):
                        _configure_file = _args[i+1];
        if (_inst_id == '' or _sign_id == ''):
                sys.exit(0);
        configuration(_sign_id,_inst_id);
        
#        print _inst_id;
#        print _sign_id;
        
#       print _configure_file;
#        configuration(_sign_id,_inst_id,0);

#        print "Input start time (in YYYYMMDDhhmmss)";
#        _start =  sys.stdin.readline().strip('\n');
#        print "Input end time (in YYYYMMDDhhmmss)";
#        _end =  sys.stdin.readline().strip('\n');
#		_inst_id = "ucla";
#		_sign_id = "/ndn/ucla.edu/xingyu";
#		_start = "19900209111111";
#		_end = "20130209111111";
#        print _option + "  " +_sign_id +"  "+_inst_id;
#        if (_option == "A"):
#               print "A here"
#               configuration(_sign_id,_inst_id, 1);
#        elif (_option == "O"):
#                print "O here"
#                configuration(_sign_id,_inst_id, 0);
