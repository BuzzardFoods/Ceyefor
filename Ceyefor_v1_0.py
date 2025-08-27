import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
import base64
import binascii
from cryptography.fernet import Fernet
import secrets
from datetime import datetime



class Ceyefor:
    def __init__(self, root):
        self.root = root
        self.root.title("Cyefor")
        self.root.configure(bg="#1a1a1a")
        self.start_time = datetime.now()  # record when program starts

        self.regen_key_every_keystroke = tk.BooleanVar(value=False)
        self.key = None

        self.setup_ui()
        self.update_clock()

    def setup_ui(self):
        # --- Top toolbar (buttons + options) ---
        top_frame = tk.Frame(self.root, bg="#1a1a1a")
        top_frame.pack(side=tk.TOP, fill=tk.X, pady=(5, 10), padx=10)

        # Left: action buttons
        button_frame = tk.Frame(top_frame, bg="#1a1a1a")
        button_frame.pack(side=tk.LEFT, anchor="nw")

        self.encrypt_file_button = tk.Button(
            button_frame, text="Encrypt File", command=self.encrypt_file,
            bg="#333333", fg="#cccccc", font=("Courier", 12)
        )
        self.encrypt_file_button.pack(pady=2, anchor="w", fill=tk.X)

        self.decrypt_file_button = tk.Button(
            button_frame, text="Decrypt File", command=self.decrypt_file,
            bg="#333333", fg="#cccccc", font=("Courier", 12)
        )
        self.decrypt_file_button.pack(pady=2, anchor="w", fill=tk.X)

        self.decrypt_message_button = tk.Button(
            button_frame, text="Decrypt Typed Message", command=self.decrypt_typed_message,
            bg="#333333", fg="#cccccc", font=("Courier", 12)
        )
        self.decrypt_message_button.pack(pady=2, anchor="w", fill=tk.X)

        self.download_button = tk.Button(
            button_frame, text="Save Encrypted Output", command=self.save_output,
            bg="#333333", fg="#cccccc", font=("Courier", 12)
        )
        self.download_button.pack(pady=2, anchor="w", fill=tk.X)

        self.save_key_button = tk.Button(
            button_frame, text="Save Key", command=self.save_key,
            bg="#333333", fg="#cccccc", font=("Courier", 12)
        )
        self.save_key_button.pack(pady=2, anchor="w", fill=tk.X)

        # Right: options
        options_frame = tk.Frame(top_frame, bg="#1a1a1a")
        options_frame.pack(side=tk.RIGHT, anchor="ne")

        self.encrypt_type = tk.StringVar(value="fernet")
        self.radio_fernet = tk.Radiobutton(
            options_frame, text="Fernet (secure, modern)",
            variable=self.encrypt_type, value="fernet",
            bg="#1a1a1a", fg="#cccccc", selectcolor="#333333", font=("Courier", 10)
        )
        self.radio_otp = tk.Radiobutton(
            options_frame, text="True OTP (paranoid mode)",
            variable=self.encrypt_type, value="otp",
            bg="#1a1a1a", fg="#cccccc", selectcolor="#333333", font=("Courier", 10)
        )
        self.radio_fernet.pack(anchor="e")
        self.radio_otp.pack(anchor="e")

        self.keymode_checkbox = tk.Checkbutton(
            options_frame,
            text="New Key Every Keystroke (F1)",
            variable=self.regen_key_every_keystroke,
            bg="#1a1a1a",
            fg="#cccccc",
            selectcolor="#333333",
            font=("Courier", 10),
            activebackground="#1a1a1a",
            activeforeground="#cccccc"
        )
        self.keymode_checkbox.pack(anchor="e", pady=(10, 0))

        # Lock the checkbox when OTP is selected
        self.encrypt_type.trace_add("write", self.on_encrypt_type_change)
        # Ensure initial state matches default selection
        self.on_encrypt_type_change()

        # --- Clock and uptimer ---
        clock_frame = tk.Frame(self.root, bg="#1a1a1a")
        clock_frame.pack(side=tk.TOP, fill=tk.X, padx=20, pady=(0, 2))

        # define StringVars here, before using them
        self.clock_var = tk.StringVar(value="--:--:--.---")
        self.elapsed_var = tk.StringVar(value="00:00:00.000")

        # uptime and clock labels
        self.clock_label = tk.Label(
            clock_frame, textvariable=self.clock_var,
            bg="#1a1a1a", fg="#7dd3fc", font=("Courier", 12)
        )

        self.elapsed_label = tk.Label(
            clock_frame, textvariable=self.elapsed_var,
            bg="#1a1a1a", fg="#7dd3fc", font=("Courier", 12),
        )
        
        self.elapsed_label.pack(side=tk.BOTTOM, anchor="e")
        self.clock_label.pack(side=tk.BOTTOM, anchor="e")

        # --- Kick off the live clock and the program uptime display
        self.update_clock()
        self.start_time = datetime.now()


        # --- Main output box (result) ---
        self.result_box = tk.Text(
            self.root, wrap=tk.WORD, bg="#0d0d0d", fg="#aaaaaa", font=("Courier", 12)
        )
        self.result_box.pack(expand=True, fill=tk.BOTH, padx=20, pady=(10, 5))

        # Optional startup message
        self.result_box.insert(
            "1.0",
            ">>> Ceyefor ready.\n"
            "Type below to encrypt in real time.\n"
            "Press F1 to toggle 'New Key Every Keystroke'.\n"
        )

        # --- Input box ---
        self.text_entry = tk.Text(
            self.root, wrap=tk.WORD, bg="#262626", fg="#ffffff",
            insertbackground="white", font=("Courier", 12), height=8
        )
        self.text_entry.pack(expand=False, fill=tk.BOTH, padx=20, pady=(5, 10))
        self.text_entry.bind("<KeyRelease>", lambda event: self.encrypt_and_convert())
      
        # F1 toggle
        self.root.bind("<F1>", self.toggle_key_regen_mode)

    ############
    
    ### rapid clock follows 
    def update_clock(self):
        now = datetime.now()
        self.clock_var.set(now.strftime("%H:%M:%S.%f")[:-3])

        elapsed = now - self.start_time
        h, remainder = divmod(int(elapsed.total_seconds()), 3600)
        m, s = divmod(remainder, 60)
        ms = int(elapsed.microseconds / 1000)
        self.elapsed_var.set(f"{h:02}:{m:02}:{s:02}.{ms:03}")

        self.root.after(33, self.update_clock) #you can adjust the clock refresh rate here
          


    def toggle_key_regen_mode(self, event=None):
        # Don’t allow toggling in OTP mode
        if self.encrypt_type.get() == "otp":
            self.regen_key_every_keystroke.set(True)
            return
        self.regen_key_every_keystroke.set(not self.regen_key_every_keystroke.get())

    
    def generate_key(self):
            return Fernet.generate_key()
        
    def generate_otp_key(self, length):
        return secrets.token_bytes(length)

    def encrypt_and_convert(self):
        text = self.text_entry.get("1.0", tk.END).strip()
        if not text:
            self.result_box.delete("1.0", tk.END)
            self.result_box.insert(tk.END, "[waiting for input...]")
            return

        hex_text = binascii.hexlify(text.encode()).decode()
        octal_text = ' '.join(format(ord(char), 'o') for char in text)

        encryption_type = self.encrypt_type.get()
        
## change below for custom text display, below are the placeholders
#############PLACEHOLDERS#############
##  {text} - the original text
##  {encrypted} - the encrypted text
#   {key} - the encryption key
#   {hex_text} - the hex representation of the text
#  {octal_text} - the octal representation of the text        
# {otp_key_b64} - the base64-encoded OTP key
# {now_ts} - the current timestamp
# {fernet} - the fernet encryption object



        if encryption_type == "fernet":
            if self.regen_key_every_keystroke.get() or not hasattr(self, 'static_key'):
              self.static_key = self.generate_key()
            key = self.static_key
            fernet = Fernet(key)
            encrypted = fernet.encrypt(text.encode())
            now_ts = datetime.now().strftime("%Y-%m-%d  %H%M %S%f")
            result = f"""
>>> --- ENCRYPTION COMPLETE (FERNET) --- <<<
{now_ts}
Original Text:
{text}

Encrypted:
{encrypted.decode()}

Encryption Key (Fernet):
{key.decode()}

Hex:
{hex_text}

Octal:
{octal_text}
"""
        else:
            if self.regen_key_every_keystroke.get() or not hasattr(self, 'static_otp'):
                self.static_otp = self.generate_otp_key(len(text))

            otp_key = self.static_otp
            encrypted_bytes = bytes([a ^ b for a, b in zip(text.encode(), otp_key)])
            encrypted = base64.b64encode(encrypted_bytes).decode()
            otp_key_b64 = base64.b64encode(otp_key).decode()

            result = f"""
>>> --- ENCRYPTION COMPLETE (TRUE OTP) --- <<<

Original Text:
{text}

Encrypted (base64-encoded XOR result):
{encrypted}

One-Time Pad Key (base64, must match exactly for decryption):
{otp_key_b64}

Hex:
{hex_text}

Octal:
{octal_text}
"""




        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, result)


    def decrypt_typed_message(self):
        encrypted_text = self.text_entry.get("1.0", tk.END).strip()
        if not encrypted_text:
            messagebox.showwarning("Missing Input", "Type or paste an encrypted message.")
            return

        key = simpledialog.askstring("Decryption Key", "Enter the base64 decryption key:")
        if not key:
            return

        encryption_type = self.encrypt_type.get()
        try:
            if encryption_type == "fernet":
                fernet = Fernet(key.encode())
                decrypted = fernet.decrypt(encrypted_text.encode()).decode()
            else:
                encrypted_bytes = base64.b64decode(encrypted_text.encode())
                otp_key = base64.b64decode(key.encode())
                decrypted = bytes([a ^ b for a, b in zip(encrypted_bytes, otp_key)]).decode()
        except Exception as e:
            decrypted = f"Decryption failed: {e}"

        self.result_box.delete("1.0", tk.END)
        self.result_box.insert(tk.END, f"Decrypted Text:\n{decrypted}")

    def save_output(self):
        data = self.result_box.get("1.0", tk.END)
        if not data.strip():
            messagebox.showwarning("Nothing to Save", "No text entered.")
            return

        # Extract only the encrypted message
        encryption_type = self.encrypt_type.get()
        encrypted = ""
        if encryption_type == "fernet":
            marker = "Encrypted:\n"
        else:
            marker = "Encrypted (base64-encoded XOR result):\n"

        if marker in data:
            encrypted = data.split(marker, 1)[1].split("\n", 1)[0].strip()
        else:
            messagebox.showerror("Error", "No encrypted message found to save.")
            return
        filetypes = [("Encrypted Files", "*.cet"),
                     ("false .exe", "*.exe"),
                     ("false .jpg", "*.jpg"),
                     ("All Files", "*.*")
                     ]
        file_path = filedialog.asksaveasfilename(defaultextension=".cet", filetypes=filetypes)
        if file_path:
            with open(file_path, "w") as f:
                f.write(encrypted)
            messagebox.showinfo("Saved", f"Encrypted message saved to:\n{file_path}")

    def save_key(self):
        data = self.result_box.get("1.0", tk.END)
        if not data.strip():
            messagebox.showwarning("Nothing to Save", "Encrypt something first, code cowboy.")
            return

        encryption_type = self.encrypt_type.get()
        key = ""
        if encryption_type == "fernet":
            marker = "Encryption Key (Fernet):\n"
        else:
            marker = "One-Time Pad Key (base64, must match exactly for decryption):\n"

        if marker in data:
            key = data.split(marker, 1)[1].split("\n", 1)[0].strip()
        else:
            messagebox.showerror("Error", "No key found to save.")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".key",
            filetypes=[
                ("Key Files", "*.key"),
                ("Text Files", "*.txt"),
                ("All Files", "*.*"),
            ]
        )
        if file_path:
            with open(file_path, "w") as f:
                f.write(key)
            messagebox.showinfo("Saved", f"Key saved to:\n{file_path}")

    def encrypt_file(self):
        filepath = filedialog.askopenfilename()
        if not filepath:
            return

        encryption_type = self.encrypt_type.get()

        if encryption_type == "otp":
            confirm = messagebox.askyesno(
                "Continue with OTP Encryption?",
                "You're about to use TRUE One-Time Pad encryption — the most secure method known.\n\n"
                "This will generate a truly random key that is EXACTLY the same size as the file.\n"
                "It will NOT work without that key.\n\n"
                "Depending on file size, this may be resource-intensive and take a while.\n\n"
                "Use this method ONLY if you're okay with:\n"
                "- Larger file size (double total)\n"
                "- No room for error\n"
                "- Maximum paranoia-level security\n\n"
                "Do you wish to continue?"
            )
            if not confirm:
                return

            with open(filepath, "rb") as f:
                data = f.read()

            otp_key = self.generate_otp_key(len(data))
            encrypted_bytes = bytes([a ^ b for a, b in zip(data, otp_key)])

            save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc"),("All Files", "*.*")])
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(encrypted_bytes)
                with open(save_path + ".key", "wb") as kf:
                    kf.write(otp_key)
                messagebox.showinfo("Success", f"OTP Encrypted file saved to:\n{save_path}\nKey saved as:\n{save_path}")

            return 

        #  Fernet encryption
        key = self.generate_key()
        fernet = Fernet(key)

        with open(filepath, "rb") as f:
            data = f.read()

        encrypted = fernet.encrypt(data)

        save_path = filedialog.asksaveasfilename(defaultextension=".enc", filetypes=[("Encrypted Files", "*.enc"),("All Files", "*.*")])
        if save_path:
            with open(save_path, "wb") as f:
                f.write(encrypted)
            with open(save_path + ".key", "wb") as kf:
                kf.write(key)
            messagebox.showinfo("Success", f"File encrypted and saved to:\n{save_path}\nKey saved as:\n{save_path}.key")

    def decrypt_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.enc"),("All Files", "*.*")])
        if not filepath:
            return

        key_path = filedialog.askopenfilename(title="Select Key File", filetypes=[("Key Files", "*.key"),("All Files", "*.*")])
        if not key_path:
            return

        with open(key_path, "rb") as kf:
            key = kf.read()

        with open(filepath, "rb") as f:
            encrypted_data = f.read()

        encryption_type = self.encrypt_type.get()

        try:
            if encryption_type == "otp":
                if len(key) != len(encrypted_data):
                    messagebox.showerror("Error", "OTP key length does not match encrypted file length.")
                    return

                decrypted = bytes([a ^ b for a, b in zip(encrypted_data, key)])
            else:
                fernet = Fernet(key)
                decrypted = fernet.decrypt(encrypted_data)

        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed:\n{e}")
            return

        save_path = filedialog.asksaveasfilename(title="Save Decrypted File")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(decrypted)
            messagebox.showinfo("Success", f"File decrypted to:\n{save_path}")

    def _draw_histogram(self, b: bytes):
        self.hist_canvas.delete("all")
        if not b:
            return
        counts = [0]*256
        for x in b:
            counts[x] += 1
        m = max(counts) or 1
        for x, c in enumerate(counts):
            h = int((c / m) * 32)
            # vertical line per byte value
            self.hist_canvas.create_line(x, 32, x, 32 - h, fill="#6aa9ff")

    def on_encrypt_type_change(self, *args):
            if self.encrypt_type.get() == "otp":
                self.regen_key_every_keystroke.set(True)
                self.keymode_checkbox.config(state="disabled")
            else:
                self.keymode_checkbox.config(state="normal")

# uninteresting comment, just wondering if anyone reads these. how's your day going? heres a joke: Why did the computer go to therapy? It had too many bytes of emotional baggage!
if __name__ == "__main__":
    root = tk.Tk()
    app = Ceyefor(root)
    root.mainloop()
