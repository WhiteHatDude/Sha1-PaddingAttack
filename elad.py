import sys
import urllib.parse
import base64
from shaext import shaext
import requests

original_sig = "a52d26378b114c214a0eebcebaec0d972a210669"
original_params = "count=2&lat=42.39561&user_id=2&long=-71.13051&waffle=dream"
add_params = "&waffle=liege"
keylen = 14

# sha1 padding
ext = shaext(original_params, keylen, original_sig)
ext.add(add_params)
data, sig = ext.final()

body = data.decode('latin-1') + "|sig:" + sig
print(body)
resp = requests.post("http://ctf.uksouth.cloudapp.azure.com:9233/orders", data=body)
# DR:
#resp = requests.post("http://ctf-dr.centralus.cloudapp.azure.com:9233/orders", data=body)

print(resp.status_code, resp.reason)
print(resp.text)