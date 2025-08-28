#!/usr/bin/env python3
"""
detector_full_candidate_name.py
Usage:
    python3 detector_full_candidate_name.py iscp_pii_dataset.csv

Reads a CSV with columns: record_id, Data_json
Outputs: redacted_output_candidate_full_name.csv with columns:
    record_id, redacted_data_json, is_pii

Notes:
- Self-contained. Uses only Python standard library.
- Masking strategy:
    * Phone (10 digits): keep first 2 and last 2 digits, mask middle with X
    * Aadhar (12 digits): keep first 4 and last 4, mask middle
    * Email: keep first 2 chars of local-part (if available) then Xs, keep domain
    * Name (full): keep first letter of first and last names, rest X (preserve spaces)
    * Passport: keep first char and last 2, mask middle
    * UPI id: keep first 2 chars of username then Xs, keep @domain
    * IP/device: mask most chars but preserve type marker
    * Address: redact entire 'address' field to "[REDACTED_PII]" if considered PII
"""

import sys
import csv
import json
import re
from collections import defaultdict

# Regexes
RE_PHONE = re.compile(r'(?:\D|^)(\d{10})(?:\D|$)')  # find contiguous 10 digits
RE_AADHAR = re.compile(r'(?:\D|^)(\d{12})(?:\D|$)')  # 12 digits
RE_PASSPORT = re.compile(r'\b([A-Z]\d{7})\b')  # Format: Letter + 7 digits (common)
RE_UPI = re.compile(r'\b([A-Za-z0-9.\-_]{1,256}@[A-Za-z0-9]{2,64})\b')  # simple upi pattern like user@bank
RE_EMAIL = re.compile(r'([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})')
RE_PIN = re.compile(r'\b\d{6}\b')  # India PIN code
RE_IPv4 = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.|$)){4}\b')
# Device id heuristic: alphanumeric strings of length >=8 in field 'device_id' or 'device' - handled by field presence

# Helper maskers
def mask_mid_keep(s, keep_first=2, keep_last=2):
    if not s:
        return s
    if len(s) <= keep_first + keep_last:
        return 'X' * len(s)
    return s[:keep_first] + 'X' * (len(s) - keep_first - keep_last) + s[-keep_last:]

def mask_email(e):
    m = RE_EMAIL.search(e or "")
    if not m:
        return "[REDACTED_PII]"
    local, domain = m.group(1), m.group(2)
    if len(local) <= 2:
        masked_local = local[0] + "X" * (len(local)-1) if len(local)>=1 else "XX"
    else:
        masked_local = local[:2] + "X" * (len(local)-2)
    return masked_local + "@" + domain

def mask_name(fullname):
    if not fullname:
        return fullname
    parts = fullname.split()
    if len(parts) == 1:
        # single name => per rules not PII alone, but masking anyway if needed
        p = parts[0]
        return p[0] + "X" * (len(p)-1) if len(p)>1 else p
    masked_parts = []
    for p in parts:
        if len(p) <= 1:
            masked_parts.append(p)
        else:
            masked_parts.append(p[0] + "X" * (len(p)-1))
    return " ".join(masked_parts)

def mask_passport(p):
    if not p:
        return p
    if len(p) <= 3:
        return "X" * len(p)
    return p[0] + "X" * (len(p)-3) + p[-2:]

def mask_upi(u):
    if not u:
        return u
    if "@" not in u:
        return "[REDACTED_PII]"
    username, domain = u.split("@",1)
    if len(username) <= 2:
        masked_user = username[0] + "X"*(len(username)-1) if len(username)>0 else "X"
    else:
        masked_user = username[:2] + "X" * (len(username)-2)
    return masked_user + "@" + domain

def mask_ip(ip):
    m = RE_IPv4.search(ip or "")
    if not m:
        return "[REDACTED_PII]"
    parts = ip.split(".")
    if len(parts) == 4:
        return parts[0] + ".X.X." + parts[-1]
    return "[REDACTED_PII]"

def detect_phone_in_field(v):
    if not v:
        return None
    # remove non-digits and get 10-digit substrings
    digs = re.findall(r'\d', str(v))
    joined = "".join(digs)
    # check any 10-digit contiguous in original value
    m = RE_PHONE.search(str(v))
    if m:
        return m.group(1)
    # fallback: if joined contains 10-digit
    if len(joined) >= 10:
        for i in range(len(joined)-9):
            candidate = joined[i:i+10]
            # accept as phone
            return candidate
    return None

def detect_aadhar_in_field(v):
    if not v:
        return None
    m = RE_AADHAR.search(str(v))
    return m.group(1) if m else None

def detect_passport_in_field(v):
    if not v:
        return None
    m = RE_PASSPORT.search(str(v))
    return m.group(1) if m else None

def detect_upi_in_field(v):
    if not v:
        return None
    m = RE_UPI.search(str(v))
    return m.group(1) if m else None

def detect_email(v):
    if not v:
        return None
    m = RE_EMAIL.search(str(v))
    return m.group(0) if m else None

def detect_ip(v):
    if not v:
        return None
    m = RE_IPv4.search(str(v))
    return m.group(0) if m else None

def is_full_name_present(data):
    # Full name exists if 'name' field with >=2 tokens OR both first_name and last_name fields non-empty
    name = data.get("name") or ""
    fn = data.get("first_name") or ""
    ln = data.get("last_name") or ""
    if fn and ln:
        if fn.strip() and ln.strip():
            return True
    if name and len(name.strip().split()) >= 2:
        return True
    return False

def is_address_present(data):
    # Address considered present if 'address' exists and contains street/city/pincode heuristics OR
    # address + pin_code field present
    addr = data.get("address") or ""
    pin = data.get("pin_code") or data.get("pin") or ""
    if addr and pin:
        # if pin looks like 6-digit anywhere
        if RE_PIN.search(str(pin)) or RE_PIN.search(str(addr)):
            return True
    # check if address contains street-like words and city keywords and a 6-digit pin
    if addr:
        if RE_PIN.search(addr):
            # likely full address with pin
            return True
        # heuristic: presence of street/road/avenue/near/blk/sector etc
        heur = ["street","st","road","rd","avenue","ave","lane","ln","sector","block","near","house","hno","flat","apt"]
        lower = addr.lower()
        if any(h in lower for h in heur) and RE_PIN.search(addr):
            return True
    # also check city + pin fields
    city = data.get("city") or ""
    if city and RE_PIN.search(str(pin)):
        return True
    return False

def mark_and_redact_record(data):
    """
    Returns (redacted_data_dict, is_pii_boolean)
    Follows the rules:
      - If any standalone PII (A) present: is_pii True and redact those A fields.
      - Else if two or more B-type items present in same record: is_pii True and redact those B fields.
      - Else is_pii False and only mask things incidentally detected? (we will not redact non-PII)
    """
    redacted = dict(data)  # shallow copy
    standalone_found = {}
    combinational_flags = {
        "name": False,
        "email": False,
        "address": False,
        "device_or_ip": False
    }

    # Detect standalone A-type
    # Phone: check known phone-like fields: phone, contact, mobile
    phone_fields = ["phone","contact","mobile","msisdn"]
    phone_val = None
    phone_field_matched = None
    for f in phone_fields:
        if f in data and data.get(f):
            candidate = detect_phone_in_field(data.get(f))
            if candidate:
                phone_val = candidate
                phone_field_matched = f
                break
    # also check 'Data_json' could contain phone, but input is JSON already parsed

    aadhar_val = None
    if "aadhar" in data and data.get("aadhar"):
        aadhar_val = detect_aadhar_in_field(data.get("aadhar"))

    passport_val = None
    if "passport" in data and data.get("passport"):
        passport_val = detect_passport_in_field(data.get("passport"))
    else:
        # sometimes passport could be in 'id' like fields - skipped for now
        passport_val = None

    upi_val = None
    if "upi_id" in data and data.get("upi_id"):
        upi_val = detect_upi_in_field(data.get("upi_id"))
    # also check username@domain style in generic fields:
    if not upi_val:
        for f,v in data.items():
            if isinstance(v,str) and "@" in v and len(v) < 200:
                # if domain looks like typical upi bank or short domain name, treat as UPI candidate
                if re.search(r'@(ybl|okaxis|axis|paytm|upi|icici|hdfc|sbi|yahoo|gmail|bank)', v, re.I):
                    upi_val = detect_upi_in_field(v)
                    if upi_val:
                        break

    # Device/IP detection
    ip_val = None
    if "ip_address" in data and data.get("ip_address"):
        ip_val = detect_ip(data.get("ip_address"))
    if not ip_val:
        # try 'ip' or 'last_login' content or 'device_id'
        if "last_login" in data and data.get("last_login"):
            ip_val = detect_ip(data.get("last_login"))
    device_val = data.get("device_id") or data.get("device") or data.get("deviceId") or None

    # Emails
    email_val = None
    if "email" in data and data.get("email"):
        email_val = detect_email(data.get("email"))

    # Names
    full_name_present = is_full_name_present(data)

    # Address presence
    address_present = is_address_present(data)

    # Determine standalone PII presence
    if phone_val:
        standalone_found['phone'] = (phone_field_matched, phone_val)
    if aadhar_val:
        standalone_found['aadhar'] = aadhar_val
    if passport_val:
        standalone_found['passport'] = passport_val
    if upi_val:
        standalone_found['upi_id'] = upi_val

    # Build combinational flags
    combinational_flags['name'] = full_name_present
    combinational_flags['email'] = bool(email_val)
    combinational_flags['address'] = address_present
    combinational_flags['device_or_ip'] = bool(device_val or ip_val)

    # Decide is_pii
    is_pii = False
    if standalone_found:
        is_pii = True
        # redact those standalone fields in redacted dict
        for k,v in standalone_found.items():
            if k == 'phone':
                fieldname, ph = v
                redacted[fieldname] = mask_mid_keep(str(ph), keep_first=2, keep_last=2)
            elif k == 'aadhar':
                # find field 'aadhar' and mask
                redacted['aadhar'] = str(aadhar_val)[:4] + "X" * (12-8) + str(aadhar_val)[-4:]
            elif k == 'passport':
                redacted['passport'] = mask_passport(passport_val)
            elif k == 'upi_id':
                # attempt to redact upi field
                # find which field contained this upi
                for fieldname,val in data.items():
                    try:
                        if isinstance(val,str) and upi_val in val:
                            redacted[fieldname] = mask_upi(upi_val)
                            break
                    except Exception:
                        continue
    else:
        # check combinational PII rule: two or more B-type present
        present_B = sum(1 for v in combinational_flags.values() if v)
        if present_B >= 2:
            is_pii = True
            # redact the B-type fields that are present
            if combinational_flags['name']:
                if data.get("name"):
                    redacted["name"] = mask_name(data.get("name"))
                if data.get("first_name") or data.get("last_name"):
                    # mask first and last separately
                    if data.get("first_name"):
                        redacted["first_name"] = mask_name(data.get("first_name"))
                    if data.get("last_name"):
                        redacted["last_name"] = mask_name(data.get("last_name"))
            if combinational_flags['email'] and email_val:
                # find any field containing email and mask
                for fieldname,val in data.items():
                    if isinstance(val,str) and email_val in val:
                        redacted[fieldname] = mask_email(email_val)
            if combinational_flags['address']:
                # redact address and pin_code
                if data.get("address"):
                    redacted["address"] = "[REDACTED_PII]"
                if data.get("pin_code"):
                    redacted["pin_code"] = "[REDACTED_PII]"
            if combinational_flags['device_or_ip']:
                if ip_val and "ip_address" in data:
                    redacted["ip_address"] = mask_ip(ip_val)
                if device_val and "device_id" in data:
                    # mask device id keeping small prefix
                    redacted["device_id"] = mask_mid_keep(str(device_val), keep_first=3, keep_last=2)

    # Even if not marked PII, still proactively mask certain fields that are standalone PII-looking but per rules should be considered:
    # However, to adhere strictly to rules, DO NOT mark non-PII as PII. We will avoid masking standalone non-PII B-items (email/name) when not combinational.

    # Return redacted dict and is_pii flag
    return redacted, bool(is_pii)

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 detector_full_candidate_name.py iscp_pii_dataset.csv")
        sys.exit(1)
    infile = sys.argv[1]
    outfile = "redacted_output_candidate_full_name.csv"

    with open(infile, newline='', encoding='utf-8') as csvfile_in, \
         open(outfile, 'w', newline='', encoding='utf-8') as csvfile_out:

        reader = csv.DictReader(csvfile_in)
        fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
        writer = csv.DictWriter(csvfile_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            rid = row.get('record_id') or row.get('id') or ''
            data_json = row.get('Data_json') or row.get('data_json') or row.get('data') or ''
            # some datasets have double-quoted JSON strings - ensure parsing
            parsed = {}
            if isinstance(data_json, str):
                try:
                    parsed = json.loads(data_json)
                except Exception:
                    # try to unescape quotes then parse
                    try:
                        parsed = json.loads(data_json.replace("'", "\""))
                    except Exception:
                        # fallback: keep as empty dict
                        parsed = {}
            elif isinstance(data_json, dict):
                parsed = data_json
            else:
                parsed = {}

            redacted_json, is_pii = mark_and_redact_record(parsed)
            # ensure JSON string is compact and escaped properly for CSV
            redacted_str = json.dumps(redacted_json, ensure_ascii=False)
            writer.writerow({
                'record_id': rid,
                'redacted_data_json': redacted_str,
                'is_pii': str(bool(is_pii))
            })

    print(f"Processed '{infile}' -> '{outfile}'")

if __name__ == "__main__":
    main()
