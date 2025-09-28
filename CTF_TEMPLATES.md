# CTF Writeup Templates

## Quick Post Template
```markdown
---
title: "Challenge Name - CTF Name 2025"
date: 2025-XX-XX XX:XX:XX +0000
categories: [CTF, Web]
tags: [ctf, writeup, web]
image:
  path: "/assets/img/2025-XX-XX-post-slug/featured.png"
  alt: "Challenge Name"
---

## Challenge Overview

**Challenge:** Challenge Name  
**Category:** Web  
**Difficulty:** Medium  
**Points:** 200  
**Solves:** 25  

Brief challenge description here.

## Analysis

Initial analysis and approach.

```bash
# Initial commands
curl -X GET http://target.com/
```

## Solution

Step-by-step solution explanation.

### Step 1: Discovery

Explanation of what you found.

```python
# Solution code
import requests
response = requests.get('http://target.com/')
```

### Step 2: Exploitation

How you exploited the vulnerability.

## Flag

```
flag{example_flag_here}
```

## Lessons Learned

- Key takeaway 1
- Key takeaway 2

---

*Thanks for reading! Feel free to reach out if you have any questions.*
```

## Quick Challenge Section
```markdown
## Challenge Name

**Category:** Web  
**Points:** 100  
**Solves:** 50  

Challenge description here.

### Solution

Solution explanation.

```bash
# Commands
curl -X POST http://target.com/login
```

**Flag:** `flag{example}`
```

## Code Snippets

### Command with Output
```console
$ ls -la
total 16
drwxr-xr-x 2 user user 4096 Sep 28 10:00 .
```

### Python Exploit Template
```python
#!/usr/bin/env python3
# Challenge Name - CTF Name
# Author: Your Name

import requests

def exploit():
    # Exploit logic here
    pass

if __name__ == "__main__":
    exploit()
```

### File Analysis
```bash
file filename
strings filename | grep -i flag
hexdump -C filename | head -20
```

### Network Analysis
```bash
nc -zv target 80
nmap -sV -sC target
```

### Binary Analysis
```bash
file binary
checksec binary
objdump -d binary | grep -A 10 "main>"
```

### Crypto Analysis
```python
# Common crypto operations
import base64
ciphertext = "encrypted_data"
plaintext = base64.b64decode(ciphertext).decode()
```
