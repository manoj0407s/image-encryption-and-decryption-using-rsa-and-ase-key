import os
import base64
import io
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from tkinter import filedialog, Label, Button, Entry, Text, Scrollbar, END, messagebox
from tkinterdnd2 import DND_FILES, TkinterDnD
from datetime import datetime
from PIL import Image  # Added for image preview

# Constants
BLOCK_SIZE = AES.block_size

# Globals
private_key_path = ""
public_key_path = ""
rsa_private_key = None
rsa_public_key = None

# Theme Toggle
is_dark_mode = False

def toggle_theme(force=None):
    global is_dark_mode
    if force is not None:
        target_dark_mode = force
    else:
        target_dark_mode = not is_dark_mode

    bg = "#2E2E2E" if target_dark_mode else "#F0F0F0"
    fg = "#FFFFFF" if target_dark_mode else "#000000"

    root.configure(bg=bg)
    for widget in root.winfo_children():
        if isinstance(widget, (Label, Button, Text, Entry)):
            widget.configure(bg=bg, fg=fg, insertbackground=fg)
        elif isinstance(widget, Scrollbar):
            widget.configure(bg=bg)
    is_dark_mode = target_dark_mode

# GUI Setup
root = TkinterDnD.Tk()
root.title("Image Encryption/Decryption with Drag-and-Drop")

# Auto-switch theme based on system time
current_hour = datetime.now().hour
if current_hour >= 19 or current_hour < 7:
    toggle_theme(force=True)
else:
    toggle_theme(force=False)

# RSA Key Save/Load
def save_rsa_keys():
    global rsa_private_key, rsa_public_key
    private_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Private Key")
    public_path = filedialog.asksaveasfilename(defaultextension=".pem", title="Save Public Key")

    if private_path and public_path:
        with open(private_path, "wb") as prv_file:
            prv_file.write(rsa_private_key.export_key())
        with open(public_path, "wb") as pub_file:
            pub_file.write(rsa_public_key.export_key())
        messagebox.showinfo("Success", "Keys saved successfully.")
        return private_path, public_path
    return None, None

def load_rsa_keys():
    global rsa_private_key, rsa_public_key
    private_path = filedialog.askopenfilename(title="Load Private Key")
    public_path = filedialog.askopenfilename(title="Load Public Key")

    if private_path and public_path:
        try:
            with open(private_path, "rb") as prv_file:
                rsa_private_key = RSA.import_key(prv_file.read())
            with open(public_path, "rb") as pub_file:
                rsa_public_key = RSA.import_key(pub_file.read())
            messagebox.showinfo("Success", "Keys loaded successfully.")
            return private_path, public_path
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load keys: {e}")
    return None, None

def regenerate_keys():
    global rsa_private_key, rsa_public_key
    rsa_key = RSA.generate(2048)
    rsa_private_key = rsa_key
    rsa_public_key = rsa_key.public_key()
    save_rsa_keys()

# AES Crypto
def aes_encrypt(data, key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ct_bytes = cipher.encrypt(pad(data, BLOCK_SIZE))
    return iv + ct_bytes

def aes_decrypt(encrypted_data, key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24, or 32 bytes.")
    iv = encrypted_data[:BLOCK_SIZE]
    ct_bytes = encrypted_data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct_bytes), BLOCK_SIZE)

# RSA Crypto
def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt(encrypted_data, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(encrypted_data)

# Image Encryption
def encrypt_image(image_path, aes_key, rsa_public_key):
    try:
        with open(image_path, "rb") as image_file:
            image_data = image_file.read()

        encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)
        encrypted_image = aes_encrypt(image_data, aes_key)

        combined_data = encrypted_aes_key + encrypted_image
        encoded_data = base64.b64encode(combined_data).decode('utf-8')
        return encoded_data
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")
        return None

# Image Decryption
def decrypt_image(encoded_data, rsa_private_key):
    try:
        combined_data = base64.b64decode(encoded_data.encode('utf-8'))
        rsa_key_size = rsa_private_key.size_in_bytes()
        encrypted_aes_key = combined_data[:rsa_key_size]
        encrypted_image = combined_data[rsa_key_size:]

        aes_key = rsa_decrypt(encrypted_aes_key, rsa_private_key)
        decrypted_image = aes_decrypt(encrypted_image, aes_key)

        return decrypted_image
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")
        return None

# GUI Logic
def browse_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, END)
    entry.insert(0, filename)

def encrypt_button_clicked():
    if not rsa_public_key:
        messagebox.showerror("Error", "No RSA public key loaded.")
        return

    image_path = image_path_entry.get()
    if not os.path.exists(image_path):
        messagebox.showerror("Error", "Invalid image path.")
        return

    try:
        aes_key = os.urandom(32)
        encoded_data = encrypt_image(image_path, aes_key, rsa_public_key)
        if encoded_data:
            result_text.delete(1.0, END)
            result_text.insert(END, encoded_data)
            messagebox.showinfo("Success", "Image encrypted successfully!")

            save_path = filedialog.asksaveasfilename(defaultextension=".txt", title="Save Encrypted Output")
            if save_path:
                with open(save_path, "w") as f:
                    f.write(encoded_data)
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_button_clicked():
    if not rsa_private_key:
        messagebox.showerror("Error", "No RSA private key loaded.")
        return

    encoded_data = result_text.get("1.0", END).strip()
    if not encoded_data:
        messagebox.showerror("Error", "No encrypted data found.")
        return

    try:
        decrypted_image = decrypt_image(encoded_data, rsa_private_key)
        if decrypted_image:
            save_path = filedialog.asksaveasfilename(defaultextension=".png", title="Save Decrypted Image")
            if save_path:
                with open(save_path, "wb") as f:
                    f.write(decrypted_image)
                messagebox.showinfo("Success", "Image decrypted and saved!")

                # Display the image
                try:
                    image = Image.open(io.BytesIO(decrypted_image))
                    image.show()
                except Exception as img_err:
                    messagebox.showerror("Error", f"Failed to preview image: {img_err}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Drag and Drop Handler
def on_file_drop(event):
    file_path = event.data.strip("{}")
    if os.path.isfile(file_path):
        image_path_entry.delete(0, END)
        image_path_entry.insert(0, file_path)

# GUI Setup
Label(root, text="Select or Drop Image:").grid(row=0, column=0, padx=5, pady=5)
image_path_entry = Entry(root, width=40)
image_path_entry.grid(row=0, column=1, padx=5, pady=5)
image_path_entry.drop_target_register(DND_FILES)
image_path_entry.dnd_bind('<<Drop>>', on_file_drop)
Button(root, text="Browse", command=lambda: browse_file(image_path_entry)).grid(row=0, column=2, padx=5, pady=5)

Button(root, text="Encrypt", command=encrypt_button_clicked).grid(row=1, column=0, columnspan=3, pady=5)
Button(root, text="Decrypt", command=decrypt_button_clicked).grid(row=2, column=0, columnspan=3, pady=5)
Button(root, text="Regenerate RSA Keys", command=regenerate_keys).grid(row=3, column=0, columnspan=3, pady=5)
Button(root, text="Load RSA Keys", command=load_rsa_keys).grid(row=4, column=0, columnspan=3, pady=5)

Label(root, text="Encrypted Output:").grid(row=5, column=0, padx=5, pady=5)
result_text = Text(root, height=10, width=50)
result_text.grid(row=6, column=0, columnspan=3, padx=5, pady=5)
scrollbar = Scrollbar(root, command=result_text.yview)
scrollbar.grid(row=6, column=3, sticky='ns')
result_text.config(yscrollcommand=scrollbar.set)

root.mainloop()
