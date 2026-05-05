# Chiper "Сахар" - Writeup
---
#### 🕳️ DarkHoleTeam @ CTF KubSTU 2026
> [!NOTE]
> This writeup was carefully written and edited for clarity after the challenge was solved.
> The tools, methodology and analysis are real - only the chaos has been omitted.
>> If something looks clean and obvious here, it wasn't during the CTF.
---
## Challenge Description

> Sugar Capybara Talks - a group of capybaras from a secret unit encrypts their communications with a proprietary protocol.
> The PCAP contains their intercepted session. They are communicating with some kind of command server.
>
> `nc 217.26.29.80:31337`
> `nc 62.113.108.12:31337`

---

## Step 1: PCAP Reconnaissance
Check what's inside the pcap
```bash
tshark -r traffic.pcap -q -z io,phs 2>/dev/null
===================================================================
Protocol Hierarchy Statistics
Filter:

eth                                      frames:6855 bytes:553798
  arp                                    frames:4 bytes:168
  ip                                     frames:6851 bytes:553630
    tcp                                  frames:5252 bytes:442049
      data                               frames:1955 bytes:217277
      http                               frames:88 bytes:9335
        http                             frames:3 bytes:2110
      _ws.malformed                      frames:1 bytes:74
    udp                                  frames:1551 bytes:106891
      data                               frames:1551 bytes:106891
    icmp                                 frames:48 bytes:4690
      data                               frames:48 bytes:4690
===================================================================
```
Identify all unique IP pairs and protocols:

```bash
tshark -r traffic.pcap -T fields \
 -e ip.src -e ip.dst -e _ws.col.Protocol 2>/dev/null | sort -u
===================================================================
                ARP
172.28.0.11     172.28.0.20     HTTP
172.28.0.11     172.28.0.20     TCP
172.28.0.11,172.28.0.20 172.28.0.20,172.28.0.11 ICMP
172.28.0.20     172.28.0.11     HTTP
172.28.0.20     172.28.0.11     TCP
172.28.0.20     172.28.0.11     UDP
```
Check which protocols use the challenge port:

```bash
tshark -r traffic.pcap -Y "tcp.port == 31337 or udp.port == 31337" \
 -T fields -e _ws.col.Protocol 2>/dev/null | sort -u
===================================================================
HTTP
TCP
```
---

## Step 2: Identifying Client and Server

SYN packets always come from the client - identify roles:
```bash
tshark -r traffic.pcap \
 -Y "tcp.port == 31337 and tcp.flags.syn == 1 and tcp.flags.ack == 0" \
 -T fields -e ip.src -e ip.dst -e tcp.dstport 2>/dev/null | sort -u
===================================================================
172.28.0.20     172.28.0.11     31337

# 172.28.0.11:31337 = SERVER
# 172.28.0.20       = CLIENT
```
Count total TCP streams on port 31337:
```bash
tshark -r traffic.pcap \ 
 -Y "tcp.port == 31337 and tcp.flags.syn==1 and tcp.flags.ack==0" \
 -T fields -e tcp.stream 2>/dev/null
===================================================================
0
1
...
343
344
```

---

## Step 3: Reading the Protocol Banner

Read the first stream - discover the proprietary protocol:
```bash
tshark -r traffic.pcap -q -z follow,tcp,ascii,0 2>/dev/null
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 0
Node 0: 172.28.0.20:43872
Node 1: 172.28.0.11:31337
        22
[SUGAR_PROTOCOL v1.0]

        22
SALT:a3f7c9b1e2d45608          # server uses this salt for key derivation

        19
CIPHER:AES-256-CBC             # encryption algorithm

        29
KDF:SHA256(PASSPHRASE||SALT)   # key derivation function

        31
>>>ENCRYPTED_CHANNEL_ACTIVE<<< # server switches to encrypted mode

783                            # клиент отправил очень достойное и уважаемое сообщение :)
HTTP/1.1 200 OK
Content-Type: text/plain

............
Prompt injection attack
............

        19
ERR: invalid frame             # server rejected the message or its format
```

### Protocol summary so far:

| Parameter | Value |
|---|---|
| Protocol | `SUGAR_PROTOCOL v1.0` |
| Salt | `a3f7c9b1e2d45608` |
| Cipher | `AES-256-CBC` |
| KDF | `SHA256(PASSPHRASE || SALT)` |
| Total streams | 344 |

---

## Step 4: Finding a Valid Stream

Most streams end with `ERR: invalid frame` - noise/spam.
We need streams where:
1. The client sent data **after** `>>>ENCRYPTED_CHANNEL_ACTIVE<<<`
2. The server did **NOT** respond with `ERR: invalid frame`

```bash
tshark -r traffic.pcap -Y "tcp.port == 31337 and tcp.flags.syn==1 and tcp.flags.ack==0" \
 -T fields -e tcp.stream 2>/dev/null | sort -un | \
 xargs -P 10 -I{} bash -c '
 c=$(tshark -r traffic.pcap -q -z follow,tcp,ascii,{} 2>/dev/null)
 echo "$c" | grep -q "ERR: invalid frame" && exit
 a=$(echo "$c" | awk "/ENCRYPTED_CHANNEL_ACTIVE/{f=1}f{print}")
 echo "$a" | grep -qP "^\d+" && echo "STREAM {}"
'
===================================================================
STREAM 51
```

Only **one** stream survived the filter - Stream 51.

---

## Step 5: Dissecting Stream 51

```bash
tshark -r traffic.pcap -q -z follow,tcp,hex,51 2>/dev/null
===================================================================
Follow: tcp,hex
Filter: tcp.stream eq 51
Node 0: 172.28.0.20:54352
Node 1: 172.28.0.11:31337
        00000000  5b 53 55 47 41 52 5f 50  52 4f 54 4f 43 4f 4c 20  [SUGAR_P ROTOCOL
        00000010  76 31 2e 30 5d 0a                                 v1.0].
        00000016  53 41 4c 54 3a 61 33 66  37 63 39 62 31 65 32 64  SALT:a3f 7c9b1e2d
        00000026  34 35 36 30 38 0a                                 45608.
        0000002C  43 49 50 48 45 52 3a 41  45 53 2d 32 35 36 2d 43  CIPHER:A ES-256-C
        0000003C  42 43 0a                                          BC.
        0000003F  4b 44 46 3a 53 48 41 32  35 36 28 50 41 53 53 50  KDF:SHA2 56(PASSP
        0000004F  48 52 41 53 45 7c 7c 53  41 4c 54 29 0a           HRASE||S ALT).
        0000005C  3e 3e 3e 45 4e 43 52 59  50 54 45 44 5f 43 48 41  >>>ENCRY PTED_CHA
        0000006C  4e 4e 45 4c 5f 41 43 54  49 56 45 3c 3c 3c 0a     NNEL_ACT IVE<<<.
# client sent a message
00000000  00 00 00 20 51 6c ec 24  ea 85 ba b5 e1 12 ac 66  ... Ql.$ .......f
00000010  0b bd a8 0d 3b 19 89 be  a3 b4 e3 0a 01 91 b3 33  ....;... .......3
00000020  08 0b aa cf                                       ....
        # server response - no ERR!
        0000007B  00 00 00 30 cf 76 fc a8  c6 60 e5 e1 62 64 f5 b4  ...0.v.. .`..bd..
        0000008B  52 94 d3 50 8b 2c 83 79  86 f5 e9 f0 3b 46 08 c5  R..P.,.y ....;F..
        0000009B  b4 6f 59 eb fd 19 ee 1a  59 7b a2 81 22 4d 50 dd  .oY..... Y{.."MP.
        000000AB  47 5b 0f 9d                                       G[..
```

---

## Step 6: Frame Format Analysis
Client frame - 36 bytes total

```
[00 00 00 20]                                      4 bytes - payload length (0x20 = 32)
[51 6c ec 24 ea 85 ba b5 e1 12 ac 66 0b bd a8 0d] 16 bytes - IV
[3b 19 89 be a3 b4 e3 0a 01 91 b3 33 08 0b aa cf] 16 bytes - ciphertext (1 AES block)
```
Frame format: [4B big-endian len][16B IV][ciphertext]

Server response - 52 bytes total
```
[00 00 00 30]                                      4 bytes - payload length (0x30 = 48)
[cf 76 fc a8 c6 60 e5 e1 62 64 f5 b4 52 94 d3 50] 16 bytes - IV
[8b 2c 83 79 86 f5 e9 f0 3b 46 08 c5 b4 6f 59 eb 
 fd 19 ee 1a 59 7b a2 81 22 4d 50 dd 47 5b 0f 9d] 32 bytes - ciphertext (2 AES blocks)
```

---

## Step 7: Reasoning About Plaintext Size

The client ciphertext is **16 bytes = exactly 1 AES block**.

With AES-256-CBC and PKCS7 padding, ciphertext size is always a multiple of 16:

| Plaintext length | Ciphertext length |
|---|---|
| 1 – 15 bytes | **16 bytes** ✅ our case |
| **16 bytes** | 32 bytes (PKCS7 adds a full padding block) ❌ |
| 17 – 31 bytes | 32 bytes ❌ |

**The passphrase is at most 1-15 characters long - very likely a common word.**

---

## Step 8: Why Brute-Force Works Here

The KDF is:
key = SHA256(PASSPHRASE | "a3f7c9b1e2d45608") salt known from PCAP

| What we know | Why it matters |
|---|---|
| SALT from PCAP | Rainbow tables are useless, but **online brute-force is possible** |
| IV from PCAP | We can attempt decryption |
| Ciphertext from PCAP | We have something to decrypt |
| Plaintext ≤ 15 bytes | Short word - almost certainly in `rockyou.txt` |
| Single SHA256, no iterations | ~500M candidates/sec on GPU - extremely fast |

> **Salt protects against Rainbow Tables, not against brute-force when the salt is public.**
> A proper KDF like `PBKDF2`, `bcrypt`, or `argon2` with thousands of iterations would make this infeasible.

If decryption produces valid PKCS7 padding **and** printable ASCII,
the password is found.

## Step 9: Brute-Force Script [bf-example.py](bf-example.py)
```bash
python3 bf-example.py
===================================================================
Password: chocolate
Client# ls
documents
drafts
flag.txt
```
At this point all messages between client & server can be decrypted.

---
## Step 10: Connecting to the Server using implemented shell [client.py](client.py)
```bash
python3 client.py
===================================================================
cat flag.txt
KubSTU{...}
```

---

## Summary

```
1. PCAP analysis     # identified SUGAR_PROTOCOL v1.0 on port 31337
2. Banner parsing    # extracted SALT, CIPHER, KDF specification
3. Stream filtering  # found 1 valid encrypted exchange: Stream 51
4. Frame analysis    # FORMAT: [4B len][16B IV][ciphertext]
                     # ciphertext = 16 bytes -> plaintext <= 15 bytes
5. KDF analysis      # key = SHA256(PASSPHRASE || SALT)
                     # SALT is public -> brute-force is feasible
                     # single SHA256, no iterations -> very fast
6. Brute-force       # rockyou.txt -> PASSPHRASE found
7. Connect to server # capture the flag
