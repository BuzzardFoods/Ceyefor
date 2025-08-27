# Ceyefor v1.0

*An experiment in encrypton, using Fernet and OneTimePad encryption. DO NOT USE THIS FOR SENSITIVE DATA, <u>IT IS NOT SECURE.</u>*

---

## ⚠️ Disclaimer

**This project is not secure. It is for learning and demonstration only.**

- State-level adversaries will easily bypass this.
- Data leaks through UI widgets, clipboard, key files, and metadata.
- OTP mode is only "perfect secrecy" in theory; in practice, key reuse/distribution/storage breaks it.
- Fernet mode uses strong crypto, but key handling in this app is insecure.

> **Bottom line:** This is a proof-of-concept. **Do not use for real privacy or sensitive data.**

---

## What is Ceyefor?

Ceyefor is a Python GUI experiment in encryption, built with Tkinter, [`cryptography`](https://cryptography.io/), and `secrets`. It was assembled with the help of AI code assistants.

**Features:**
- Encrypt/decrypt text in real time
- Switch between Fernet (AES + HMAC) and a naïve OTP (XOR)
- Encrypt/decrypt files (Fernet only)
- Visualize entropy with simple metrics
- Save/load ciphertext and keys

The interface has an old-school hacker vibe and is mainly for exploration and entertainment.

---

## Known Flaws

- Keys and ciphertext are displayed together in the UI
- Keys are saved next to ciphertext by default
- OTP mode truncates if text and byte lengths mismatch
- OTP mode has no integrity check (malleable ciphertext)
- Tkinter widgets and clipboard leak secrets into memory/swap/history

---

## How to Run

```bash
git clone https://github.com/buzzardfoods/ceyefor.git
cd ceyefor
pip install cryptography #only if you don't have cyptography package installed
python ceyefor.py
```

Requires **Python 3.8+**, with the ``cyptography`` package.

---

## How to Use 
<sub>   (Optional: Spray paint keyboard. Call a friend over and say "Annnnnd.....we're in.")</sub>
1. Launch the app.
2. Choose Fernet (modern) or OTP (demo).
3. Type text to see live encryption, keys, and hex/octal views.
4. Use buttons to encrypt/decrypt files (Fernet only).
5. Save ciphertext/keys for experimentation (not for real security).

---

## Purpose

- Practice Tkinter GUI programming
- Experiment with Fernet
- Visualize randomness and entropy
- Demonstrate why home-rolled crypto is fragile
- Kill time
- Make me seem like I know what I'm talking about

---

## Lessons

- Crypto math is easy; operational security is where things fail.
- OTP is only perfect if keys are truly random, exchanged offline, used once, and never stored with ciphertext.
- Fernet is reliable if used correctly, but mishandling keys defeats it.
- Real security means using vetted tools and handling keys properly.
- If a state level actor want's your data, they have it. Don't break any laws. 
---

## Closing Note

<p align=center>Ceyefor is a fun project to help me better understand security flaws. It is NOT to be taken seriously as a tool for security, <u>It's not a secure method of file or information storage or transmission. </u>

---
