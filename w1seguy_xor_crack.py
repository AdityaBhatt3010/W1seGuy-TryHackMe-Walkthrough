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
