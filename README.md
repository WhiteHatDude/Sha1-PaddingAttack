# Sha1-PaddingAttack
This code was copied from https://gist.github.com/philfreo/3873715 because I wanted to make sure it is always available.

# Python 3 support
I have spent few hours to make this tool work with Python 3.x.x now instead of the original python 2.17.x

# Usage
To use the code download all 3 *.py files in the repo to a local folder and create a new .py file with the following:
```Python
from shaext import shaext

#origtext = the original text that was hashed using sha1.
#keylen = the length of the key used with the sha1.
#origsig = the sha1 signature value
ext = shaext(origtext, keylen, origsig)

#addtext = the extra text you want to add to the original text (from above)
ext.add(addtext)

#final will return the new null padded byte coded text + the corresponding new compromised sha1 signature as text.
data, sig = ext.final()
```

For more info on Sha1 padding attack check: https://www.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks
