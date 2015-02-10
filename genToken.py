#!/usr/bin/env python

import sys
import random
import string

# Generates a token to use for DNSWATCH

# read commandline and do some error checks
email=str(sys.argv[1])
if "@" not in email:
 print "Usage: genWatchToken.py myemail@domain"
 sys.exit(1)
# store everything before @domain.tld and cleanup
name=email[:email.find('@')].replace('.','')
# append 32 char long random token to email
token=name+''.join(random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(32))
# output in format: token,emailaddress
print repr(token+","+email)
