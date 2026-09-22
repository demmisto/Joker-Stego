#!/usr/bin/env python3
"""
StegoSuite - A Python GUI Steganography Tool
==============================================
Hide and extract secret text messages inside Image (PNG/BMP), Audio (WAV),
and Text (TXT) files using LSB (Least Significant Bit) and zero-width
character techniques.

Dependencies:
    pip install pillow

Run:
    python stego_tool.py
"""

import os
import wave
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from PIL import Image
except ImportError:
    Image = None


# ----------------------------------------------------------------------
# Helper functions: bit <-> byte conversion, simple XOR "encryption"
# ----------------------------------------------------------------------

def text_to_bits(data: bytes) -> str:
    return ''.join(format(byte, '08b') for byte in data)


def bits_to_bytes(bits: str) -> bytes:
    # bits length must be multiple of 8
    n = len(bits) - (len(bits) % 8)
    bits = bits[:n]
    return bytes(int(bits[i:i + 8], 2) for i in range(0, n, 8))


def xor_cipher(data: bytes, password: str) -> bytes:
    """Simple reversible XOR obfuscation. Not strong crypto, just a light
    layer so casual viewers of extracted bytes can't read the message
    without the password."""
    if not password:
        return data
    key = password.encode('utf-8')
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def build_payload(message: str, password: str) -> bytes:
    """32-bit big-endian length header + (optionally XORed) message bytes."""
    msg_bytes = message.encode('utf-8')
    msg_bytes = xor_cipher(msg_bytes, password)
    header = struct.pack('>I', len(msg_bytes))
    return header + msg_bytes


def payload_bit_length(message: str) -> int:
    return (4 + len(message.encode('utf-8'))) * 8


# ----------------------------------------------------------------------
# IMAGE STEGANOGRAPHY (LSB on RGB channels of PNG/BMP/etc.)
# ----------------------------------------------------------------------

class ImageSteg:
    HEADER_BITS = 32  # bits used to store payload length

    @staticmethod
    def capacity_bytes(image_path: str) -> int:
        img = Image.open(image_path)
        img = img.convert('RGB')
        w, h = img.size
        total_bits = w * h * 3
        return (total_bits - ImageSteg.HEADER_BITS) // 8

    @staticmethod
    def encode(image_path: str, message: str, password: str, output_path: str):
        if Image is None:
            raise RuntimeError("Pillow is not installed. Run: pip install pillow")

        img = Image.open(image_path)
        img = img.convert('RGB')
        pixels = list(img.getdata())
        w, h = img.size

        payload = build_payload(message, password)
        bits = text_to_bits(payload)

        capacity_bits = w * h * 3
        if len(bits) > capacity_bits:
            raise ValueError(
                f"Message too large for this image. Max ~{(capacity_bits // 8) - 4} bytes, "
                f"got {len(payload) - 4} bytes."
            )

        bit_idx = 0
        new_pixels = []
        for pixel in pixels:
            pixel = list(pixel)
            for c in range(3):  # R, G, B
                if bit_idx < len(bits):
                    pixel[c] = (pixel[c] & ~1) | int(bits[bit_idx])
                    bit_idx += 1
            new_pixels.append(tuple(pixel))
            if bit_idx >= len(bits):
                break

        # append any remaining pixels unchanged
        if bit_idx >= len(bits):
            idx_done = len(new_pixels)
            new_pixels.extend(pixels[idx_done:])

        out_img = Image.new('RGB', (w, h))
        out_img.putdata(new_pixels)

        # Force lossless format if user picked a lossy extension
        ext = os.path.splitext(output_path)[1].lower()
        if ext in ('.jpg', '.jpeg'):
            output_path = os.path.splitext(output_path)[0] + '.png'
        out_img.save(output_path)
        return output_path

    @staticmethod
    def decode(image_path: str, password: str) -> str:
        if Image is None:
            raise RuntimeError("Pillow is not installed. Run: pip install pillow")

        img = Image.open(image_path)
        img = img.convert('RGB')
        pixels = list(img.getdata())

        flat_bits = []
        for pixel in pixels:
            for c in range(3):
                flat_bits.append(str(pixel[c] & 1))

        if len(flat_bits) < 32:
            raise ValueError("No hidden data found (image too small / not encoded).")

        header_bits = ''.join(flat_bits[:32])
        msg_len = struct.unpack('>I', bits_to_bytes(header_bits))[0]

        total_needed_bits = 32 + msg_len * 8
        if len(flat_bits) < total_needed_bits:
            raise ValueError("Hidden data appears corrupted or incomplete.")

        payload_bits = ''.join(flat_bits[32:total_needed_bits])
        msg_bytes = bits_to_bytes(payload_bits)
        msg_bytes = xor_cipher(msg_bytes, password)
        try:
            return msg_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Wrong password or corrupted data.")


# ----------------------------------------------------------------------
# AUDIO STEGANOGRAPHY (LSB on raw sample bytes of WAV files)
# ----------------------------------------------------------------------

class AudioSteg:
    HEADER_BITS = 32

    @staticmethod
    def encode(audio_path: str, message: str, password: str, output_path: str):
        with wave.open(audio_path, 'rb') as wf:
            params = wf.getparams()
            frames = bytearray(wf.readframes(wf.getnframes()))

        payload = build_payload(message, password)
        bits = text_to_bits(payload)

        if len(bits) > len(frames):
            max_bytes = (len(frames) // 8) - 4
            raise ValueError(
                f"Message too large for this audio file. Max ~{max_bytes} bytes."
            )

        for i, bit in enumerate(bits):
            frames[i] = (frames[i] & ~1) | int(bit)

        with wave.open(output_path, 'wb') as out_wf:
            out_wf.setparams(params)
            out_wf.writeframes(bytes(frames))
        return output_path

    @staticmethod
    def decode(audio_path: str, password: str) -> str:
        with wave.open(audio_path, 'rb') as wf:
            frames = bytearray(wf.readframes(wf.getnframes()))

        if len(frames) < AudioSteg.HEADER_BITS:
            raise ValueError("No hidden data found (file too small).")

        header_bits = ''.join(str(b & 1) for b in frames[:32])
        msg_len = struct.unpack('>I', bits_to_bytes(header_bits))[0]

        total_needed_bits = 32 + msg_len * 8
        if len(frames) < total_needed_bits:
            raise ValueError("Hidden data appears corrupted or incomplete.")

        payload_bits = ''.join(str(b & 1) for b in frames[32:total_needed_bits])
        msg_bytes = bits_to_bytes(payload_bits)
        msg_bytes = xor_cipher(msg_bytes, password)
        try:
            return msg_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Wrong password or corrupted data.")


# ----------------------------------------------------------------------
# TEXT FILE STEGANOGRAPHY (zero-width characters appended at end of file)
# ----------------------------------------------------------------------

class TextSteg:
    ZW0 = '\u200b'  # zero width space  -> bit 0
    ZW1 = '\u200c'  # zero width non-joiner -> bit 1
    START = '\u2060'  # word joiner marks start of hidden block
    END = '\u2061'    # function application marks end of hidden block

    @staticmethod
    def encode(text_path: str, message: str, password: str, output_path: str):
        with open(text_path, 'r', encoding='utf-8', errors='replace') as f:
            original = f.read()

        payload = build_payload(message, password)
        bits = text_to_bits(payload)
        hidden = TextSteg.START + ''.join(
            TextSteg.ZW1 if b == '1' else TextSteg.ZW0 for b in bits
        ) + TextSteg.END

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(original + hidden)
        return output_path

    @staticmethod
    def decode(text_path: str, password: str) -> str:
        with open(text_path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()

        if TextSteg.START not in content or TextSteg.END not in content:
            raise ValueError("No hidden data found in this text file.")

        start = content.index(TextSteg.START) + 1
        end = content.index(TextSteg.END)
        hidden_seq = content[start:end]

        bits = ''.join('1' if ch == TextSteg.ZW1 else '0' for ch in hidden_seq if ch in (TextSteg.ZW0, TextSteg.ZW1))
        if len(bits) < 32:
            raise ValueError("Hidden data appears corrupted or incomplete.")

        header_bits = bits[:32]
        msg_len = struct.unpack('>I', bits_to_bytes(header_bits))[0]
        payload_bits = bits[32:32 + msg_len * 8]
        msg_bytes = bits_to_bytes(payload_bits)
        msg_bytes = xor_cipher(msg_bytes, password)
        try:
            return msg_bytes.decode('utf-8')
        except UnicodeDecodeError:
            raise ValueError("Wrong password or corrupted data.")


# ----------------------------------------------------------------------
# Utility: detect stego type from file extension
# ----------------------------------------------------------------------

IMAGE_EXTS = {'.png', '.bmp', '.tiff', '.tif', '.gif'}
AUDIO_EXTS = {'.wav'}
TEXT_EXTS = {'.txt'}


def detect_type(path: str):
    ext = os.path.splitext(path)[1].lower()
    if ext in IMAGE_EXTS:
        return 'Image'
    if ext in AUDIO_EXTS:
        return 'Audio'
    if ext in TEXT_EXTS:
        return 'Text'
    return None


# ----------------------------------------------------------------------
# GUI
# ----------------------------------------------------------------------

class StegoApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("StegoSuite - Steganography Tool")
        self.geometry("640x560")
        self.resizable(False, False)
        self.configure(bg="#1e1e2e")

        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except tk.TclError:
            pass
        style.configure('TNotebook', background="#1e1e2e")
        style.configure('TFrame', background="#1e1e2e")
        style.configure('TLabel', background="#1e1e2e", foreground="#e0e0e0", font=('Segoe UI', 10))
        style.configure('Header.TLabel', font=('Segoe UI', 14, 'bold'), foreground="#89b4fa")
        style.configure('TButton', font=('Segoe UI', 10))
        style.configure('TRadiobutton', background="#1e1e2e", foreground="#e0e0e0")

        notebook = ttk.Notebook(self)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)

        self.hide_tab = HideFrame(notebook)
        self.extract_tab = ExtractFrame(notebook)

        notebook.add(self.hide_tab, text='  Hide Message  ')
        notebook.add(self.extract_tab, text='  Extract Message  ')


class BaseFrame(ttk.Frame):
    def pick_file(self, entry_var, filetypes):
        path = filedialog.askopenfilename(filetypes=filetypes)
        if path:
            entry_var.set(path)
        return path

    def make_file_row(self, parent, label, var, filetypes, row):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky='w', pady=6)
        entry = ttk.Entry(parent, textvariable=var, width=52)
        entry.grid(row=row, column=1, padx=6)
        btn = ttk.Button(parent, text="Browse...",
                          command=lambda: self.pick_file(var, filetypes))
        btn.grid(row=row, column=2)


class HideFrame(BaseFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.file_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.type_var = tk.StringVar(value='Image')

        ttk.Label(self, text="Hide a Secret Message", style='Header.TLabel').grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(10, 15), padx=10)

        filetypes = [
            ("All supported", "*.png *.bmp *.tiff *.tif *.gif *.wav *.txt"),
            ("Image files", "*.png *.bmp *.tiff *.tif *.gif"),
            ("Audio files", "*.wav"),
            ("Text files", "*.txt"),
        ]
        self.make_file_row(self, "Cover file:", self.file_var, filetypes, row=1)
        self.file_var.trace_add('write', self.on_file_change)

        ttk.Label(self, text="Detected type:").grid(row=2, column=0, sticky='w', pady=6, padx=10)
        self.type_label = ttk.Label(self, text="—", foreground="#a6e3a1")
        self.type_label.grid(row=2, column=1, sticky='w')

        ttk.Label(self, text="Secret message:").grid(row=3, column=0, sticky='nw', pady=6, padx=10)
        self.msg_text = tk.Text(self, width=52, height=8, bg="#313244", fg="#f5f5f5", insertbackground='white')
        self.msg_text.grid(row=3, column=1, columnspan=2, pady=6)

        ttk.Label(self, text="Password (optional):").grid(row=4, column=0, sticky='w', pady=6, padx=10)
        pw_entry = ttk.Entry(self, textvariable=self.pass_var, show='*', width=30)
        pw_entry.grid(row=4, column=1, sticky='w')

        self.capacity_label = ttk.Label(self, text="", foreground="#f9e2af")
        self.capacity_label.grid(row=5, column=0, columnspan=3, sticky='w', padx=10, pady=(0, 6))

        hide_btn = ttk.Button(self, text="Hide Message →  Save Output File", command=self.run_hide)
        hide_btn.grid(row=6, column=0, columnspan=3, pady=15)

        self.status_label = ttk.Label(self, text="", foreground="#a6e3a1", wraplength=580, justify='left')
        self.status_label.grid(row=7, column=0, columnspan=3, sticky='w', padx=10)

    def on_file_change(self, *args):
        path = self.file_var.get()
        if not path or not os.path.exists(path):
            self.type_label.config(text="—")
            self.capacity_label.config(text="")
            return
        t = detect_type(path)
        self.type_var.set(t or '')
        self.type_label.config(text=t or "Unsupported file type")
        if t == 'Image' and Image is not None:
            try:
                cap = ImageSteg.capacity_bytes(path)
                self.capacity_label.config(text=f"Approx. capacity: {cap} bytes of text")
            except Exception:
                self.capacity_label.config(text="")
        elif t == 'Audio':
            try:
                with wave.open(path, 'rb') as wf:
                    cap = (len(wf.readframes(wf.getnframes())) // 8) - 4
                self.capacity_label.config(text=f"Approx. capacity: {cap} bytes of text")
            except Exception:
                self.capacity_label.config(text="")
        else:
            self.capacity_label.config(text="")

    def run_hide(self):
        path = self.file_var.get().strip()
        message = self.msg_text.get('1.0', 'end').rstrip('\n')
        password = self.pass_var.get()

        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid cover file.")
            return
        if not message:
            messagebox.showerror("Error", "Please enter a message to hide.")
            return

        t = detect_type(path)
        if t is None:
            messagebox.showerror("Error", "Unsupported file type. Use PNG/BMP/GIF/TIFF, WAV, or TXT.")
            return
        if t == 'Image' and Image is None:
            messagebox.showerror("Error", "Pillow is not installed. Run: pip install pillow")
            return

        ext = os.path.splitext(path)[1]
        default_name = os.path.splitext(os.path.basename(path))[0] + "_stego" + ext
        save_types = {
            'Image': [("PNG image", "*.png"), ("Bitmap image", "*.bmp")],
            'Audio': [("WAV audio", "*.wav")],
            'Text': [("Text file", "*.txt")],
        }[t]
        output_path = filedialog.asksaveasfilename(
            defaultextension=os.path.splitext(default_name)[1],
            initialfile=default_name,
            filetypes=save_types
        )
        if not output_path:
            return

        self.status_label.config(text="Working...", foreground="#f9e2af")
        self.update_idletasks()

        def worker():
            try:
                if t == 'Image':
                    out = ImageSteg.encode(path, message, password, output_path)
                elif t == 'Audio':
                    out = AudioSteg.encode(path, message, password, output_path)
                else:
                    out = TextSteg.encode(path, message, password, output_path)
                self.status_label.config(
                    text=f"✔ Success! Hidden message saved to:\n{out}",
                    foreground="#a6e3a1")
            except Exception as e:
                self.status_label.config(text=f"✘ Error: {e}", foreground="#f38ba8")

        threading.Thread(target=worker, daemon=True).start()


class ExtractFrame(BaseFrame):
    def __init__(self, parent):
        super().__init__(parent)
        self.file_var = tk.StringVar()
        self.pass_var = tk.StringVar()

        ttk.Label(self, text="Extract a Hidden Message", style='Header.TLabel').grid(
            row=0, column=0, columnspan=3, sticky='w', pady=(10, 15), padx=10)

        filetypes = [
            ("All supported", "*.png *.bmp *.tiff *.tif *.gif *.wav *.txt"),
            ("Image files", "*.png *.bmp *.tiff *.tif *.gif"),
            ("Audio files", "*.wav"),
            ("Text files", "*.txt"),
        ]
        self.make_file_row(self, "Stego file:", self.file_var, filetypes, row=1)

        ttk.Label(self, text="Detected type:").grid(row=2, column=0, sticky='w', pady=6, padx=10)
        self.type_label = ttk.Label(self, text="—", foreground="#a6e3a1")
        self.type_label.grid(row=2, column=1, sticky='w')
        self.file_var.trace_add('write', self.on_file_change)

        ttk.Label(self, text="Password (if used):").grid(row=3, column=0, sticky='w', pady=6, padx=10)
        pw_entry = ttk.Entry(self, textvariable=self.pass_var, show='*', width=30)
        pw_entry.grid(row=3, column=1, sticky='w')

        extract_btn = ttk.Button(self, text="Extract Hidden Message", command=self.run_extract)
        extract_btn.grid(row=4, column=0, columnspan=3, pady=15)

        ttk.Label(self, text="Recovered message:").grid(row=5, column=0, sticky='nw', padx=10)
        self.result_text = tk.Text(self, width=62, height=12, bg="#313244", fg="#f5f5f5", insertbackground='white')
        self.result_text.grid(row=6, column=0, columnspan=3, padx=10, pady=6)

        self.status_label = ttk.Label(self, text="", foreground="#a6e3a1", wraplength=580, justify='left')
        self.status_label.grid(row=7, column=0, columnspan=3, sticky='w', padx=10)

    def on_file_change(self, *args):
        path = self.file_var.get()
        if not path or not os.path.exists(path):
            self.type_label.config(text="—")
            return
        t = detect_type(path)
        self.type_label.config(text=t or "Unsupported file type")

    def run_extract(self):
        path = self.file_var.get().strip()
        password = self.pass_var.get()

        if not path or not os.path.exists(path):
            messagebox.showerror("Error", "Please select a valid stego file.")
            return

        t = detect_type(path)
        if t is None:
            messagebox.showerror("Error", "Unsupported file type. Use PNG/BMP/GIF/TIFF, WAV, or TXT.")
            return
        if t == 'Image' and Image is None:
            messagebox.showerror("Error", "Pillow is not installed. Run: pip install pillow")
            return

        self.status_label.config(text="Working...", foreground="#f9e2af")
        self.result_text.delete('1.0', 'end')
        self.update_idletasks()

        def worker():
            try:
                if t == 'Image':
                    msg = ImageSteg.decode(path, password)
                elif t == 'Audio':
                    msg = AudioSteg.decode(path, password)
                else:
                    msg = TextSteg.decode(path, password)
                self.result_text.delete('1.0', 'end')
                self.result_text.insert('1.0', msg)
                self.status_label.config(text="✔ Message extracted successfully.", foreground="#a6e3a1")
            except Exception as e:
                self.status_label.config(text=f"✘ Error: {e}", foreground="#f38ba8")

        threading.Thread(target=worker, daemon=True).start()


if __name__ == '__main__':
    app = StegoApp()
    app.mainloop()
