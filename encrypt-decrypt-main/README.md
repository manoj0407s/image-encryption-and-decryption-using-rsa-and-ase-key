
 🛡️ Image Encryption/Decryption with Drag-and-Drop (AES + RSA)

A Python desktop application that allows you to encrypt and decrypt images securely using a combination of AES and RSA encryption.  
Designed with a simple drag-and-drop GUI, automatic light/dark mode switch based on system time, and RSA key management


 🚀 Features

- 📂 Drag and Drop image support.
- 🔐 AES Encryption for image data.
- 🔒 RSA Encryption for AES keys.
- 🌑 Auto Light/Dark Mode (based on time).
- 🔑 Generate, Load, and Save RSA key pairs.
- 🖼️ Image Preview after decryption.
- 📝 Save Encrypted Output to a file.
- 🧩 Simple, clean Tkinter + TkinterDnD2 interface.


🛠️ How It Works

- Encryption:
  1. AES key is generated randomly.
  2. Image data is encrypted using AES (CBC mode).
  3. AES key is encrypted using RSA public key.
  4. Encrypted key + encrypted image data are combined and base64 encoded.

- Decryption:
  1. Base64 data is decoded and separated.
  2. AES key is recovered using RSA private key.
  3. Image data is decrypted using the recovered AES key.


 🖥️ Requirements

- Python 3.7+
- Required Python libraries:
  
  pip install pycryptodome tkinterdnd2 pillow
  

 📸 Screenshots

| Light Mode | Dark Mode |
|:----------:|:---------:|
| ![Light](assets/light_mode.png) | ![Dark](assets/dark_mode.png) |


 ⚙️ Installation and Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/image-encryption-dnd.git
   cd image-encryption-dnd
   ```

2. **Install the dependencies:**
   bash
   pip install -r requirements.txt

3. Run the application:
   bash
   python app.py

 📂 Project Structure

```bash
image-encryption-dnd/
├── assets/         # (Optional) Screenshots and icons
├── app.py          # Main application code
├── README.md       # Project documentation
├── requirements.txt # Dependencies
```

---

 📄 Requirements.txt Example

```txt
pycryptodome
tkinterdnd2
pillow
```

 🔮 Future Improvements

- Add drag-and-drop decryption support.
- Encrypt metadata along with the image.
- Add password-based AES key derivation (optional feature).
- Improve error handling and validations.
- Package into an .exe using PyInstaller.

---

 🤝 Contributing

Pull requests are welcome!  
Feel free to open issues or suggest features.

---

 📜 License

This project is licensed under the [MIT License](LICENSE).

---

 ❤️ Acknowledgments

- [PyCryptodome](https://www.pycryptodome.org/)
- [TkinterDnD2](https://sourceforge.net/projects/tkinterdnd/)
- [Pillow (PIL Fork)](https://python-pillow.org/)
