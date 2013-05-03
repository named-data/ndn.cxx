
#include <ndn.cxx.h>
#include <iostream>

using namespace std;

ndn::Name InterestBaseName;

// create a global handler
ndn::Wrapper handler;

void OnInterest (ndn::Name name, ndn::Selectors selectors)
{
  cerr << name << endl;
  
  static int COUNTER = 0;

  ostringstream os;
  os << "C++ LINE #" << (COUNTER++) << endl;
  
  handler.publishData (name, os.str (), 5);
}

int
main (int argc, char **argv)
{
  InterestBaseName = ndn::Name ("ccnx:/my-local-prefix/simple-fetch/file");

  handler.setInterestFilter (InterestBaseName, OnInterest);
  
  while (true)
    {
      sleep (1);
    }
  return 0;
}
