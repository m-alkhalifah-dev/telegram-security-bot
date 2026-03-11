"""
Crypto & Encoding Tools Module
Text encoding/decoding, hash generation, password generation, deep SSL/TLS analysis
"""

import asyncio
import base64
import hashlib
import math
import re
import secrets
import socket
import ssl
import string
from datetime import datetime
from typing import Optional
from urllib.parse import quote, unquote


ENCODE_TYPES = ['b64', 'hex', 'url', 'bin', 'rot13', 'md5', 'sha1', 'sha256']
DECODE_TYPES = ['b64', 'hex', 'url', 'bin', 'rot13']
HASH_ALGOS   = ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']

_ROT13_TABLE = str.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
)


async def encode_text(enc_type: str, text: str) -> str:
    """Encode text: b64 / hex / url / bin / rot13 / md5 / sha1 / sha256"""
    enc = enc_type.lower()
    result = f"🔡 *Encode — {enc.upper()}*\n\n"
    preview = text[:50] + ('...' if len(text) > 50 else '')
    result += f"Input: `{preview}`\n\n"

    try:
        if enc == 'b64':
            out = base64.b64encode(text.encode()).decode()
            result += f"✅ *Base64:*\n`{out}`"
        elif enc == 'hex':
            out = text.encode().hex()
            result += f"✅ *Hex:*\n`{out}`"
        elif enc == 'url':
            out = quote(text, safe='')
            result += f"✅ *URL Encoded:*\n`{out}`"
        elif enc == 'bin':
            out = ' '.join(format(ord(c), '08b') for c in text)
            result += f"✅ *Binary:*\n`{out[:400]}`"
        elif enc == 'rot13':
            out = text.translate(_ROT13_TABLE)
            result += f"✅ *ROT13:*\n`{out}`"
        elif enc == 'md5':
            out = hashlib.md5(text.encode()).hexdigest()
            result += f"✅ *MD5:*\n`{out}`"
        elif enc == 'sha1':
            out = hashlib.sha1(text.encode()).hexdigest()
            result += f"✅ *SHA-1:*\n`{out}`"
        elif enc == 'sha256':
            out = hashlib.sha256(text.encode()).hexdigest()
            result += f"✅ *SHA-256:*\n`{out}`"
        else:
            result += f"❌ Unknown type: `{enc}`\n"
            result += f"Supported: `{', '.join(ENCODE_TYPES)}`"
    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def decode_text(dec_type: str, text: str) -> str:
    """Decode text: b64 / hex / url / bin / rot13"""
    dec = dec_type.lower()
    result = f"🔓 *Decode — {dec.upper()}*\n\n"
    preview = text[:60] + ('...' if len(text) > 60 else '')
    result += f"Input: `{preview}`\n\n"

    try:
        if dec == 'b64':
            padded = text + '=' * (4 - len(text) % 4)
            out = base64.b64decode(padded).decode('utf-8', errors='replace')
            result += f"✅ *Decoded:*\n`{out}`"
        elif dec == 'hex':
            clean = text.replace(' ', '').replace('0x', '').replace('\\x', '')
            out = bytes.fromhex(clean).decode('utf-8', errors='replace')
            result += f"✅ *Decoded:*\n`{out}`"
        elif dec == 'url':
            out = unquote(text)
            result += f"✅ *Decoded:*\n`{out}`"
        elif dec == 'bin':
            groups = text.split()
            out = ''.join(chr(int(b, 2)) for b in groups if b)
            result += f"✅ *Decoded:*\n`{out}`"
        elif dec == 'rot13':
            out = text.translate(_ROT13_TABLE)
            result += f"✅ *Decoded:*\n`{out}`"
        else:
            result += f"❌ Unknown type: `{dec}`\n"
            result += f"Supported: `{', '.join(DECODE_TYPES)}`\n"
            result += "\nNote: MD5/SHA are one-way — they cannot be decoded."
    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def gen_hash(algorithm: str, text: str) -> str:
    """Generate hash of text using MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512"""
    algo = algorithm.lower()
    result = f"#️⃣ *Hash Generation — {algorithm.upper()}*\n\n"
    preview = text[:50] + ('...' if len(text) > 50 else '')
    result += f"Input: `{preview}`\n\n"

    hash_funcs = {
        'md5':    hashlib.md5,
        'sha1':   hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
    }

    if algo not in hash_funcs:
        result += f"❌ Unknown algorithm: `{algorithm}`\n"
        result += f"Supported: `{', '.join(hash_funcs)}`"
        return result

    try:
        h = hash_funcs[algo](text.encode()).hexdigest()
        result += f"✅ *{algorithm.upper()}:*\n`{h}`\n\n"
        result += f"├ Input length: {len(text)} chars\n"
        result += f"└ Hash length: {len(h)} hex chars ({len(h)*4} bits)"
    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def gen_password(length: int) -> str:
    """Generate a cryptographically secure random password"""
    result = "🔑 *Secure Password Generator*\n\n"

    if length < 8:
        length = 8
        result += "⚠️ Minimum length is 8 — using 8\n\n"
    elif length > 128:
        length = 128
        result += "⚠️ Maximum length is 128 — using 128\n\n"

    try:
        lower   = string.ascii_lowercase
        upper   = string.ascii_uppercase
        digits  = string.digits
        symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?'
        pool    = lower + upper + digits + symbols

        def make_password():
            # Guarantee one of each character class
            pw = [
                secrets.choice(lower),
                secrets.choice(upper),
                secrets.choice(digits),
                secrets.choice(symbols),
            ] + [secrets.choice(pool) for _ in range(length - 4)]
            secrets.SystemRandom().shuffle(pw)
            return ''.join(pw)

        passwords = [make_password() for _ in range(4)]

        result += f"✅ *Generated Passwords ({length} chars):*\n"
        for pw in passwords:
            result += f"`{pw}`\n"

        entropy = length * math.log2(len(pool))
        result += f"\n📊 *Stats:*\n"
        result += f"├ Character pool: {len(pool)} chars\n"
        result += f"├ Entropy: ~{entropy:.0f} bits\n"
        result += f"└ Generator: `secrets.SystemRandom()` (CSPRNG)\n"
        result += "\n⚠️ *Store securely — not shown again*"

    except Exception as e:
        result += f"❌ *Error:* `{str(e)}`"

    return result


async def cert_scan(domain: str) -> str:
    """Deep SSL/TLS analysis: protocols, cipher, certificate chain, vulnerability indicators"""
    domain = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    result = f"🔐 *Deep SSL/TLS Scan:* `{domain}`\n\n"

    loop = asyncio.get_event_loop()

    # ── Certificate info ──────────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()

        def get_cert():
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    return ssock.getpeercert(), ssock.cipher(), ssock.version()

        cert, cipher, tls_version = await loop.run_in_executor(None, get_cert)

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer',  []))
        not_before = cert.get('notBefore', 'Unknown')
        not_after  = cert.get('notAfter',  'Unknown')
        san = cert.get('subjectAltName', [])

        expiry    = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
        days_left = (expiry - datetime.now()).days
        exp_emoji = "✅" if days_left > 30 else ("⚠️" if days_left > 0 else "❌")

        result += "📋 *Certificate:*\n"
        result += f"├ Subject CN: `{subject.get('commonName', 'N/A')}`\n"
        result += f"├ Issuer: `{issuer.get('organizationName', 'N/A')}`\n"
        result += f"├ Valid from: `{not_before}`\n"
        result += f"├ Expires: `{not_after}`\n"
        result += f"├ Days left: {exp_emoji} *{days_left}* days\n"
        if san:
            result += f"├ SANs ({len(san)}):\n"
            for stype, sval in san[:5]:
                result += f"│  └ `{sval}`\n"
        result += "\n"

        # TLS connection details
        result += "🔒 *TLS Connection:*\n"
        result += f"├ Protocol: `{tls_version}`\n"
        if cipher:
            result += f"├ Cipher suite: `{cipher[0]}`\n"
            result += f"├ Key bits: `{cipher[2]}`\n"

        ratings = {
            'TLSv1.3': '✅ Excellent (latest)',
            'TLSv1.2': '✅ Good',
            'TLSv1.1': '⚠️ Deprecated',
            'TLSv1':   '❌ Obsolete — vulnerable',
            'SSLv3':   '💀 Critical — highly vulnerable',
        }
        result += f"└ Rating: {ratings.get(tls_version, '❓ Unknown')}\n\n"

    except ssl.SSLError as e:
        result += f"❌ *SSL Error:* `{str(e)}`\n"
        return result
    except socket.timeout:
        return result + "⏰ *Timeout* — port 443 did not respond"
    except Exception as e:
        return result + f"❌ *Error:* `{str(e)}`"

    # ── TLS version probing ────────────────────────────────────────────────────
    result += "🧪 *Protocol Support:*\n"
    for proto_flag, label, is_insecure in [
        (getattr(ssl, 'OP_NO_TLSv1_3', None),   'TLS 1.3', False),
        (None,                                    'TLS 1.2', False),
        (getattr(ssl, 'OP_NO_TLSv1_1', None),   'TLS 1.1', True),
        (getattr(ssl, 'OP_NO_TLSv1',   None),   'TLS 1.0', True),
    ]:
        try:
            test_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            test_ctx.check_hostname = False
            test_ctx.verify_mode = ssl.CERT_NONE

            # Force only this protocol version (best-effort)
            if label == 'TLS 1.0' and hasattr(ssl, 'OP_NO_TLSv1_1') and hasattr(ssl, 'OP_NO_TLSv1_2'):
                test_ctx.options |= ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            elif label == 'TLS 1.1' and hasattr(ssl, 'OP_NO_TLSv1') and hasattr(ssl, 'OP_NO_TLSv1_2'):
                test_ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_2

            def try_connect(c=test_ctx):
                with socket.create_connection((domain, 443), timeout=3) as s:
                    with c.wrap_socket(s, server_hostname=domain):
                        pass
                return True

            await asyncio.wait_for(loop.run_in_executor(None, try_connect), timeout=4)
            mark = "⚠️ Supported (insecure — disable)" if is_insecure else "✅ Supported"
            result += f"├ {label}: {mark}\n"
        except Exception:
            result += f"├ {label}: ✅ Not supported\n"

    result += "\n"

    # ── Vulnerability indicators ───────────────────────────────────────────────
    result += "🔍 *Vulnerability Indicators:*\n"
    cipher_name = cipher[0] if cipher else ''
    cipher_bits = int(cipher[2]) if cipher and cipher[2] else 256

    checks = [
        ('BEAST',   'TLS 1.0 + CBC cipher',     tls_version == 'TLSv1' and 'CBC' in cipher_name),
        ('FREAK',   'Export-grade cipher',       'EXPORT' in cipher_name or 'EXP-' in cipher_name),
        ('LOGJAM',  'Weak DHE key exchange',     'DHE' in cipher_name and cipher_bits < 2048),
        ('RC4',     'RC4 cipher in use',         'RC4' in cipher_name),
        ('3DES',    '3DES cipher in use',        '3DES' in cipher_name or 'DES-CBC3' in cipher_name),
    ]
    for name, desc, vuln in checks:
        result += f"├ {'⚠️' if vuln else '✅'} {name}: {desc + ' — detected!' if vuln else 'Not detected'}\n"

    result += "\n💡 For comprehensive testing, use: `testssl.sh` or SSL Labs (ssllabs.com)\n"
    return result
