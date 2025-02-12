#!/usr/bin/env python
# http://www.vnsecurity.net/t/length-extension-attack/
# sha1 padding/length extension attack
# by rd@vnsecurity.net
#

import sys
import base64
from shaext import shaext

if len(sys.argv) != 5:
    print("usage: %s <keylen> <original_message> <original_signature> <text_to_append>" % sys.argv[0])
    sys.exit(0)
    
keylen = int(sys.argv[1])
orig_msg = sys.argv[2]
orig_sig = sys.argv[3]
add_msg = sys.argv[4]

ext = shaext(orig_msg, keylen, orig_sig)
ext.add(add_msg)

(new_msg, new_sig) = ext.final()
        
print("new msg: " + repr(new_msg))
print("base64: " + base64.b64encode(new_msg))
print("new sig: " + new_sig)
