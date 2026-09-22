<!-- HEADER -->
<div align="center">
```
 ██████╗██╗  ██╗ █████╗  ██████╗ ███████╗
██╔════╝██║  ██║██╔══██╗██╔═══██╗██╔════╝
██║     ███████║███████║██║   ██║███████╗
██║     ██╔══██║██╔══██║██║   ██║╚════██║
╚██████╗██║  ██║██║  ██║╚██████╔╝███████║
 ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
```
`Why so serious about your secrets?`
> *"If you're good at hiding something, never do it for free."*
![Python](https://img.shields.io/badge/Python-3.8%2B-green?style=for-the-badge&logo=python&logoColor=white&color=2b2b2b)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational?style=for-the-badge&color=1a1a1a)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge&color=8b0000)
![GUI](https://img.shields.io/badge/GUI-Tkinter-purple?style=for-the-badge&color=3d0066)
![Chaos](https://img.shields.io/badge/Chaos%20Level-Maximum-critical?style=for-the-badge&color=ff4500)
</div>
---
🃏 What Is This?
StegoSuite is a Python GUI tool for hiding and extracting secret messages inside ordinary files — images, audio, and text — without leaving a visible trace. No network traffic. No cloud. Just pure, local, beautiful chaos embedded in the least significant bits of reality.
It's not about the message. It's about sending a message.
---
⚡ Features
Capability	Method	Supported Formats
🖼️ Image Steganography	LSB on RGB channels	`PNG`, `BMP`, `TIFF`, `GIF`
🔊 Audio Steganography	LSB on raw WAV frames	`WAV`
📄 Text Steganography	Zero-width Unicode chars	`TXT`
🔐 XOR Obfuscation	Password-keyed cipher	All carriers
📦 Capacity Detection	Shows max bytes before encode	Image & Audio
🧵 Threaded Processing	Non-blocking encode/decode	All
> **Steganography ≠ Encryption.** XOR obfuscation is a light layer — not a cryptographic guarantee. Pair with GPG or AES if you need real secrecy.
---
🎭 How It Works
Image — LSB on RGB
Every pixel has three channels: R, G, B. Each channel is 1 byte. The least significant bit of each byte is imperceptible to the human eye — but it's a perfect place to hide data.
```
Original pixel:  R=11001010  G=10110111  B=00110100
Hidden bit:             ↓           ↓           ↓
Stego pixel:     R=11001011  G=10110110  B=00110101
```
A 32-bit header stores payload length, followed by the XOR-obfuscated message bits, threaded through pixels left-to-right.
Audio — LSB on WAV Frames
Same principle, different carrier. Raw PCM sample bytes each contribute 1 LSB. Inaudible delta. Maximum concealment.
Text — Zero-Width Unicode
The sneakiest trick in the deck. Zero-width characters (`U+200B`, `U+200C`) are invisible in rendered text but distinct at the byte level. Messages are encoded as a sequence of these ghosts, sandwiched between Unicode markers `U+2060` and `U+2061`, and appended to any `.txt` file.
To any reader: just text. To the tool: a secret.
---
🚀 Installation
```bash
# Clone the chaos
git clone https://github.com/yourusername/stegosuite.git
cd stegosuite

# Install the one dependency
pip install pillow

# Run it
python stego_tool.py
```
> **Requirements:** Python 3.8+, `Pillow` (for image support). Audio and text modes need nothing beyond stdlib.
---
🎪 Usage
The GUI has two tabs:
🃏 Hide Message
Click Browse → select your cover file (image, WAV, or TXT)
The tool auto-detects the type and shows available capacity
Type your secret message
Set an optional password (XOR obfuscation layer)
Click Hide Message → Save Output File
Save the stego file — visually/audibly identical to the original
🃏 Extract Message
Click Browse → select the stego file
Enter the password if one was used
Click Extract Hidden Message
Message appears in the output box
---
📐 Architecture
```
stego_tool.py
│
├── Helpers
│   ├── text_to_bits()      # bytes → binary string
│   ├── bits_to_bytes()     # binary string → bytes
│   ├── xor_cipher()        # XOR obfuscation with key cycling
│   └── build_payload()     # 32-bit length header + XOR'd message bytes
│
├── ImageSteg               # LSB on RGB pixel channels (Pillow)
│   ├── capacity_bytes()    # max bytes this image can carry
│   ├── encode()            # embed payload into copy of image
│   └── decode()            # extract and decode payload
│
├── AudioSteg               # LSB on WAV frame bytes (stdlib wave)
│   ├── encode()
│   └── decode()
│
├── TextSteg                # Zero-width Unicode (stdlib only)
│   ├── encode()
│   └── decode()
│
└── GUI
    ├── StegoApp            # root Tk window + notebook
    ├── HideFrame           # "Hide Message" tab
    └── ExtractFrame        # "Extract Message" tab
```
---
⚠️ Limitations & Gotchas
JPEG is lossy — it destroys LSB data. The tool auto-converts JPEG output to PNG.
Audio must be WAV (PCM) — compressed formats will corrupt the payload.
XOR is not encryption — a determined analyst with the extracted bytes and a dictionary attack can crack weak passwords. Use this for concealment, not true confidentiality.
No steganalysis resistance — chi-square or RS analysis will detect LSB embedding in statistically uniform images (solid colors, gradients). Use complex natural photos for cover.
---
🦇 Disclaimer
This tool is built for educational purposes, CTF challenges, digital forensics research, and exploring steganographic techniques. Using it to conceal data in communications where disclosure is legally required, or to evade lawful monitoring, is your problem — not mine.
> *"Madness is like gravity. All it takes is a little push."*
Use responsibly. Or don't. I'm a README, not a cop.
---
<div align="center">
Made with chaos, Python, and a complete lack of concern for normalcy.
`¿Por qué tan serio?`
</div>
