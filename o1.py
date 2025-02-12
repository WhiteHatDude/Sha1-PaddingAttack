#!/usr/bin/env python3
import struct

import requests

# -----------------------------------------
# Utilities
# -----------------------------------------

def _leftrotate(value: int, shift: int) -> int:
    """
    Left rotate a 32-bit integer value by shift bits.
    """
    return ((value << shift) & 0xffffffff) | (value >> (32 - shift))

def sha1_padding(message_length: int) -> bytes:
    """
    Return the standard SHA-1 padding for a message of length `message_length` bytes.
    """
    # Start with the 0x80 byte.
    padding = b"\x80"
    # Zero pad so that (message_length + 1 + zeros) % 64 = 56.
    zero_pad_len = (56 - (message_length + 1) % 64) % 64
    padding += b"\x00" * zero_pad_len
    # Append the original message length in bits as a 64-bit big-endian integer.
    padding += struct.pack(">Q", message_length * 8)
    return padding

# -----------------------------------------
# Minimal SHA-1 Implementation
# -----------------------------------------

class SHA1:
    """
    A minimal SHA-1 class that supports updating data,
    setting a custom internal state (for length extension), and
    producing a digest.
    """

    def __init__(self) -> None:
        # SHA-1 initial constants
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0

        self._buffer = b""
        self._count = 0  # total number of bytes processed

    def _compress(self, chunk: bytes) -> None:
        w = list(struct.unpack(">16I", chunk))
        for i in range(16, 80):
            val = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            w.append(_leftrotate(val, 1))

        a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4
        for i in range(80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (_leftrotate(a, 5) + f + e + k + w[i]) & 0xffffffff
            e, d, c, b, a = d, c, _leftrotate(b, 30), a, temp

        self.h0 = (self.h0 + a) & 0xffffffff
        self.h1 = (self.h1 + b) & 0xffffffff
        self.h2 = (self.h2 + c) & 0xffffffff
        self.h3 = (self.h3 + d) & 0xffffffff
        self.h4 = (self.h4 + e) & 0xffffffff

    def update(self, data: bytes) -> None:
        self._count += len(data)
        self._buffer += data

        while len(self._buffer) >= 64:
            block = self._buffer[:64]
            self._buffer = self._buffer[64:]
            self._compress(block)

    def digest(self) -> bytes:
        """
        Return the final digest without modifying the current state.
        """
        temp = SHA1()
        temp.h0, temp.h1, temp.h2 = self.h0, self.h1, self.h2
        temp.h3, temp.h4 = self.h3, self.h4
        temp._count = self._count
        temp._buffer = self._buffer
        return temp._final()

    def hexdigest(self) -> str:
        return self.digest().hex()

    def _final(self) -> bytes:
        total_bytes = self._count
        # Standard padding: a single 0x80 byte, then zeros, then the length in bits.
        padding = b"\x80"
        pad_len = (56 - (total_bytes + 1) % 64) % 64
        padding += b"\x00" * pad_len
        padding += struct.pack(">Q", total_bytes * 8)
        self.update(padding)
        return struct.pack(">5I", self.h0, self.h1, self.h2, self.h3, self.h4)

    def set_state(self, h0: int, h1: int, h2: int, h3: int, h4: int, total_len: int) -> None:
        """
        Manually set the internal SHA-1 state and total length.
        :param total_len: Total number of bytes processed so far.
        """
        self.h0 = h0
        self.h1 = h1
        self.h2 = h2
        self.h3 = h3
        self.h4 = h4
        self._count = total_len
        self._buffer = b""

# -----------------------------------------
# Length Extension Helper Class
# -----------------------------------------

class Sha1LengthExtension:
    """
    A helper class to perform a SHA-1 length extension attack.

    Usage Example:
        original_sig = "5ac29325a27e7f079563c9c1913fd8862d3dbf98"
        original_params = "count=2&lat=42.39561&user_id=2&long=-71.13051&waffle=dream"
        add_params = "&waffle=liege"
        keylen = 14

        ext = Sha1LengthExtension(original_params, keylen, original_sig)
        ext.add(add_params)
        data, sig = ext.final()
    """

    def __init__(self, original_msg: str, key_length: int, original_hex_sig: str) -> None:
        """
        :param original_msg: The known original message (string).
        :param key_length:   The attacker's guess of the secret key's byte length.
        :param original_hex_sig: The original SHA-1 signature (hex) computed as SHA1(key || original_msg).
        """
        # Store the original message as bytes.
        self.original_msg = original_msg.encode('utf-8')
        self.key_length = key_length

        # Convert the original signature from hex to five 32-bit words.
        raw_sig = bytes.fromhex(original_hex_sig)
        h = struct.unpack(">5I", raw_sig)

        # --- FIX: Adjust the total length to include the glue padding ---
        # Compute the length of (key || original_msg).
        real_total = key_length + len(self.original_msg)
        # Compute the glue padding for that length.
        self.glue_padding = sha1_padding(real_total)
        # The forged hash must continue from a state where the total processed bytes include the glue padding.
        forged_total = real_total + len(self.glue_padding)

        # Initialize our forged SHA-1 with the recovered internal state and updated count.
        self.forged_sha = SHA1()
        self.forged_sha.set_state(h[0], h[1], h[2], h[3], h[4], forged_total)

        # Buffer for the extension data to be appended.
        self.extension_buffer = b""

    def add(self, data: str) -> None:
        """
        Append additional data to the forged message.
        :param data: The string to add.
        """
        self.extension_buffer += data.encode('utf-8')

    def final(self):
        """
        Finalize the length extension attack.
        :return: A tuple (forged_data, forged_signature_hex) where:
                 - forged_data is the complete forged message that would be processed as:
                   key || original_msg || glue_padding || extension
                 - forged_signature_hex is the new valid SHA-1 signature (hex string).
        """
        # Continue the hash with the extension data.
        self.forged_sha.update(self.extension_buffer)
        forged_digest = self.forged_sha.digest()
        forged_hex_sig = forged_digest.hex()

        # Construct the final message that the server will see.
        forged_data = self.original_msg + self.glue_padding + self.extension_buffer

        return forged_data, forged_hex_sig

# -----------------------------------------
# Example Usage
# -----------------------------------------

if __name__ == "__main__":
    original_sig = "a52d26378b114c214a0eebcebaec0d972a210669"
    original_params = "count=2&lat=42.39561&user_id=2&long=-71.13051&waffle=dream"
    add_params = "&waffle=liege"
    keylen = 14

    ext = Sha1LengthExtension(original_params, keylen, original_sig)
    ext.add(add_params)
    data, sig = ext.final()

    print("[+] Forged data:", data)
    print("[+] Forged sig:", sig)
    
    body = data.decode('latin-1') + "|sig:" + sig
    print(body)
    resp = requests.post("http://ctf.uksouth.cloudapp.azure.com:9233/orders", data=body)
    # DR:
    #resp = requests.post("http://ctf-dr.centralus.cloudapp.azure.com:9233/orders", data=body)

    print(resp.status_code, resp.reason)
    print(resp.text)