# 🧠 W1seGuy | TryHackMe Walkthrough – XOR? BrUt3\_F0rC3 iT 🗿

📍 **Lab Link:** [https://tryhackme.com/room/w1seguy](https://tryhackme.com/room/w1seguy)

🔒 **Category:** Cryptography
🧪 **Techniques:** XOR Decryption, Brute Force, CyberChef, Python Automation
⚡ **Difficulty:** Beginner–Intermediate
🔑 **Flags:** 2 (XOR Key + Final Flag)

---

## 🧩 TL;DR

Welcome back, cyber sleuths. Today we’re cracking down the **W1seGuy** room on TryHackMe — a sleek XOR-based CTF that forces you to mix brain 🧠 with brute 🦍.

We’ll walk through:

* XOR logic
* Reverse-engineering a random encryption key
* Using CyberChef for quick PoC 🧑‍🍳
* Brute-forcing with Python (because brute > guess 🗿)

---

## 🧪 Task 1: Analyze the Source Code 🧐

You’re given a Python source file. This is the full code provided by TryHackMe:

```python
import random
import socketserver 
import socket, os
import string

flag = open('flag.txt','r').read().strip()

def send_message(server, message):
    enc = message.encode()
    server.send(enc)

def setup(server, key):
    flag = 'THM{thisisafakeflag}' 
    xored = ""

    for i in range(0,len(flag)):
        xored += chr(ord(flag[i]) ^ ord(key[i%len(key)]))

    hex_encoded = xored.encode().hex()
    return hex_encoded

def start(server):
    res = ''.join(random.choices(string.ascii_letters + string.digits, k=5))
    key = str(res)
    hex_encoded = setup(server, key)
    send_message(server, "This XOR encoded text has flag 1: " + hex_encoded + "\n")
    
    send_message(server,"What is the encryption key? ")
    key_answer = server.recv(4096).decode().strip()

    try:
        if key_answer == key:
            send_message(server, "Congrats! That is the correct key! Here is flag 2: " + flag + "\n")
            server.close()
        else:
            send_message(server, 'Close but no cigar' + "\n")
            server.close()
    except:
        send_message(server, "Something went wrong. Please try again. :)\n")
        server.close()

class RequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        start(self.request)

if __name__ == '__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    server = socketserver.ThreadingTCPServer(('0.0.0.0', 1337), RequestHandler)
    server.serve_forever()
```

This code sets up a TCP server, generates a **random 5-character key**, XORs the flag with it, and sends the encoded hex to the client. If the user replies with the correct key, they get **flag 2**.

---

## 🛰️ Phase 1 – Netcat & Recon

```bash
nc MACHINE_IP 1337
```

Sample output:

```
This XOR encoded text has flag 1: 8d6e6445643e5d...
What is the encryption key?
```

✅ Save that hex string — it’s your encrypted **flag 1**.

---

## 🧠 XOR Weakness – Known Plaintext FTW

We know TryHackMe flags begin with `THM{`. This is called a **known-plaintext attack** in cryptography. Here's the trick:

1. Take the first 4 bytes of the encoded string.
2. XOR them with `T`, `H`, `M`, `{` respectively.
3. You’ll get the first 4 characters of the key!

### Example:

* Encoded: `8d6e6445...`
* `T` = `0x54`, `H` = `0x48`, `M` = `0x4D`, `{` = `0x7B`
* XOR with hex values → You get key prefix: `8ndE`

👑 We're halfway to the full key.

---

## 🧑‍🍳 Quick CyberChef PoC

1. Input: Your encrypted string (in hex).
2. Operation 1: From Hex
3. Operation 2: XOR with `THM{`
4. Boom — output is the key prefix.

But brute-forcing the **5th character** manually? That ain’t it. Time to automate.

---

## 💣 Phase 2 – Python Brute Forcer 🦍

Let’s brute-force the rest of the key and decode the flag.

---

### 🧨 `w1seguy_xor_crack.py`

```python
import binascii
import string
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

def xor_bytes(data, key):
    return bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(data)])

def find_initial_key(encrypted_hex, known_plaintext):
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    return ''.join([chr(b ^ ord(known_plaintext[i])) for i, b in enumerate(encrypted_bytes[:len(known_plaintext)])])

def brute_force_key(encrypted_hex, known_prefix="THM{", known_suffix="}"):
    encrypted_bytes = binascii.unhexlify(encrypted_hex)
    key_prefix = find_initial_key(encrypted_hex, known_prefix)
    print(f"[+] Discovered key prefix: {key_prefix}")

    charset = string.ascii_letters + string.digits
    remaining_length = 5 - len(key_prefix)

    def try_key(key):
        full_key = key_prefix + key
        decrypted = xor_bytes(encrypted_bytes, full_key).decode(errors='ignore')
        if decrypted.startswith(known_prefix) and decrypted.endswith(known_suffix):
            return full_key, decrypted
        return None

    found = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        tasks = {
            executor.submit(try_key, ''.join(candidate)): ''.join(candidate)
            for candidate in itertools.product(charset, repeat=remaining_length)
        }
        for future in as_completed(tasks):
            result = future.result()
            if result:
                found.append(result)
                break

    return found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="XOR Key Brute Forcer for W1seGuy Challenge")
    parser.add_argument("-e", "--encrypted", required=True, help="Hex encoded XOR ciphertext")
    args = parser.parse_args()

    print("[*] Starting brute-force...")
    results = brute_force_key(args.encrypted)

    if results:
        for key, flag in results:
            print(f"\n[+] Key Found: {key}")
            print(f"[+] Decrypted Flag: {flag}")
    else:
        print("[-] No matching flag found.")
```

---

## 🧪 Sample Execution

```bash
python3 w1seguy_xor_crack.py -e 8d6e6445643e5d...
```

Output:

```
[+] Discovered key prefix: 8ndE
[+] Key Found: 8ndEw
[+] Decrypted Flag: THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}
```

---

### 🏁 Flag 1:

```
THM{p1alntExtAtt4ckcAnr3alLyhUrty0urxOr}
```

Enter the key `8ndEw` back into Netcat to get:

---

### 🏁 Flag 2:

```
THM{BrUt3_ForC1nG_XOR_cAn_B3_FuN_nO?}
```

---

## 👋 Goodbye Note

That’s a wrap on this W1seGuy adventure!
We dived into XOR encryption, uncovered flaws using known plaintext, and let Python do the heavy lifting with brute force. Whether you solved it with CyberChef wizardry or script-fu, remember — every CTF makes you wiser, sharper, and more unstoppable 🧠⚔️

Until the next challenge...
**Keep hacking, stay curious, and never stop thinking like a 🗿.**

*– Aditya Bhatt | 0xM4jest1cF1res*

---
