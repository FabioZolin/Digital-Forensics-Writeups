**Category:** Network Forensics / Cryptography
**Difficulty:** Medium 
**Objective:** Analyze a PCAP capture of a compromised service, decrypt QUIC traffic, identify the data exfiltrated, and reconstruct the flag based on attacker metadata.

## 1. Initial Reconnaissance

I started with the provided packet capture file (`Chal.pcap`). 
Upon opening it in Wireshark, I noticed the **QUIC** protocol traffic and its encryption. 
Since QUIC traffic is encrypted by default (TLS 1.3), standard analysis was impossible without session keys.

To identify potential unencrypted data leaks or C2 (Command & Control) beacons before attempting complex decryption, I decided to scan the raw packet payloads for readable strings. Using the filtering function on wireshark, I filtered for keywords associated with key exchanges or initialization vectors, having success with the filter:
`"frame contains "handshake_init"`

This filter brought me to a set of suspicious packets containing JSON payloads in plain text, distinct from the other encrypted QUIC streams:

```
JSON
{
  "type": "handshake_init",
  "seed": "af717e2c8789db71fe624598faba3953c23fdb685e6b8cd2e6f84beef0c57175",
  "salt": "telemetry",
  "info": "sslkeylog"
}
```

Further inspection of nearby packets revealed a follow-up packet containing encrypted data and a nonce: 

```
JSON
{
  "type": "telemetry_sslkeylog",
  "nonce_b64": "S459VmTWtpNcz+NU",
  "ct_b64": "...",
  "tag_b64": "..."
}
```
**Hypothesis:** The attacker triggered a vulnerability to force the server to dump its **SSLKEYLOG** (session secrets), encrypted it using a derived key, and exfiltrated it via this side-channel to decrypt the traffic later.

## 2. Cryptoanalysis: Decrypting the SSL Secrets

The JSON parameters (`seed`, `salt`, `info`) strongly suggested an **HKDF (HMAC-based Key Derivation Function)** mechanism. 
The presence of a `nonce` and `tag` in the data packet indicated **AES-GCM** encryption.

I wrote a Python script to derive the encryption key from the seed and decrypt the payload to recover the SSL keys and see the traffic.

### Solver Script (SSL Decrypt)

Python

```
import base64
import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# 1. Configuration with data from "handshake_init"

seed_hex = "af717e2c8789db71fe624598faba3953c23fdb685e6b8cd2e6f84beef0c57175"

salt = b"telemetry"

info = b"sslkeylog"

# 2. Getting the key (HKDF-SHA256)
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    info=info,
)

key = hkdf.derive(binascii.unhexlify(seed_hex))

# 3. Data from "telemetry_sslkeylog", there were 2 different chunks

# Chunk 0 (Source 120)
nonce0 = base64.b64decode("S459VmTWtpNcz+NU")
ct0 = base64.b64decode("D4Y706RkRpgzXAOAWe4eKyE...")
tag0 = base64.b64decode("ElHxGRAt7wicOe+lFkLiaw==")

# Chunk 1 (Source 121)
nonce1 = base64.b64decode("tXd5ku7fU1lPn/D9")
ct1 = base64.b64decode("o6vvBmgm6Iyj9/RRUjDdqtcFj6...")
tag1 = base64.b64decode("ZlYYx1K6YiALxD0Tm9k6/w==")

# 4. Decryption (AES-GCM)
aesgcm = AESGCM(key)

try:
    pt0 = aesgcm.decrypt(nonce0, ct0 + tag0, None)
    pt1 = aesgcm.decrypt(nonce1, ct1 + tag1, None)
    full_ssl_log = pt0.decode('utf-8') + pt1.decode('utf-8')
    print("\n[+] Successful decryption! See the keys in keys.log")
    with open("keys.log", "w") as f:
        f.write(full_ssl_log)

    print("Saved in 'keys.log'.")

except Exception as e:
    print(f"[-] Error during decryption: {e}")
```

At this point i was able to see the http3 traffic clearly.

## 3. Investigating Internal Data Access

With full visibility into the **HTTP/3** streams, I analyzed the requests sent by the attacker.

I see a GET request followed by a response which contained a .tar.gzip file, as i could see by:
1) The filename contained in the header
2) The magic bytes `1f 8b 08` at the start of the "data" section of the frame

After extracting and opening the archive i found a .env file, with said contents:
```
AES_FLAG_KEY=wEN64tLF1PtOglz3Oorl7su8_GQzmlU2jbFP70cFz7c=
DEBUG=True
SECRET_KEY=dev_secret_123
```

The following request from the attacker was `GET /flag`.
Investigating the HTTP/3 response headers, I noticed the **Content-Type** was set to `application/octet-stream`, indicating a raw data transfer rather than a standard web page.

The response body contained a JSON object (or raw string) starting with `gAAAAA...`. Based on the recovered source code using the `cryptography` library and the format of the string (Version 0x80 + Timestamp + HMAC), I identified this as a **Fernet** token.

## 4. Decrypting the Flag

Using the `AES_FLAG_KEY` found in the exfiltrated `.env` file and the token from the `/flag` response, I could finally decrypt the flag content.

### Solver Script (Flag Decrypt)

Python

```
from cryptography.fernet import Fernet

# Key found in the exfiltrated .env file
key = b'wEN64tLF1PtOglz3Oorl7su8_GQzmlU2jbFP70cFz7c='

# Token found in the HTTP/3 response to /flag
token = b'gAAAAABpNXDCHUJ4YqH0Md2p6tzE303L8z5kPpPPWwYYrXUdiyW89eCaWWL1dbYU2JYj7SUvdwqySW_egZDRF0fyFGxPua2KoFmd8upKP7cZv55jVp_SzItA='

f = Fernet(key)
print(f"Flag Part 2: {f.decrypt(token).decode()}")
```

**Result:** `qu1c_d4t4gr4m_pwn3d`

## 5. Attacker Attribution & Flag Construction

The challenge required the flag in the format: `nite{attacker_ip_attacker_CID_flag_part_2}`.

I analyzed the decrypted traffic flow to attribute the attack:

1. **Attacker IP:** I identified the IP address _initiating_ the requests (e.g., `GET /flag`) as **192.0.2.66**.
    
2. **Attacker CID (Connection ID):** In QUIC, the Destination CID (DCID) in a packet identifies the receiver. I inspected a packet sent from the Server (`203.0.113.100`) **to** the Attacker (`192.0.2.66`). The DCID in this packet represents the Attacker's ID.
    
    - **CID found:** `2457ce19cb87e0eb`
        

### Final Flag

Combining the gathered intelligence:

`nite{192.0.2.66_2457ce19cb87e0eb_qu1c_d4t4gr4m_pwn3d}`
