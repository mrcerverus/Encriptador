import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from tkinter import Tk, filedialog, Button, Label, Entry, messagebox, Frame


# Base logica
class AESFileEncryptor:
    def __init__(self, password: str):
        self.password = password.encode()
        self.backend = default_backend()
        self.block_size = algorithms.AES.block_size

    def derive_key(self, password: bytes, salt: bytes = None) -> (bytes, bytes):
        if salt is None:
            salt = os.urandom(16)  # Generate random salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend,
        )
        return salt, kdf.derive(password)  # Return salt and derived key

    def encrypt(self, input_file: str, output_file: str):
        try:
            with open(input_file, "rb") as f:
                plaintext = f.read()
            
            salt, key = self.derive_key(self.password)
            iv = os.urandom(16)  # Initialization vector
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            encryptor = cipher.encryptor()
            
            padder = PKCS7(self.block_size).padder()
            padded_data = padder.update(plaintext) + padder.finalize()
            ciphertext = encryptor.update(padded_data) + encryptor.finalize()
            
            with open(output_file, "wb") as f:
                f.write(salt + iv + ciphertext)  # Write salt, IV, and ciphertext
            return True
        except Exception as e:
            print(f"Error durante la encriptación: {e}")
            return False

    def decrypt(self, input_file: str, output_file: str):
        try:
            with open(input_file, "rb") as f:
                data = f.read()
            
            salt = data[:16]  # Extract salt
            iv = data[16:32]  # Extract IV
            ciphertext = data[32:]  # Extract ciphertext
            
            _, key = self.derive_key(self.password, salt=salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
            decryptor = cipher.decryptor()
            
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            unpadder = PKCS7(self.block_size).unpadder()
            plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

            with open(output_file, "wb") as f:
                f.write(plaintext)
            print(f"Archivo desencriptado guardado como: {output_file}")
            return True
        except Exception as e:
            print(f"Error durante la desencriptación: {e}")
            return False


#GUI aplicativo
class AESFileEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("AES Encryptor")
        self.master.geometry("400x300")
        self.master.configure(bg="#282c34")

        # Header Frame
        header = Frame(master, bg="#61afef")
        header.pack(fill="x", pady=10)

        title = Label(header, text="ENCRIPTADOR MILITAR", font=("Helvetica", 16, "bold"), bg="#61afef", fg="#282c34")
        title.pack(pady=10)

        # Main Frame
        main_frame = Frame(master, bg="#282c34")
        main_frame.pack(pady=10)

        # Password Input
        self.password_label = Label(main_frame, text="Contraseña:", font=("Helvetica", 12), bg="#282c34", fg="#abb2bf")
        self.password_label.pack(pady=10)

        self.password_entry = Entry(main_frame, show="*", font=("Helvetica", 12), width=30, bg="#3e4451", fg="#dcdfe4")
        self.password_entry.pack(pady=10)

        # Buttons
        self.encrypt_button = Button(
            main_frame, text="Seleccionar archivo para encriptar", font=("Helvetica", 12),
            bg="#e06c75", fg="#ffffff", relief="flat", command=self.encrypt_file
        )
        self.encrypt_button.pack(pady=10, fill="x")

        self.decrypt_button = Button(
            main_frame, text="Seleccionar archivo para desencriptar", font=("Helvetica", 12),
            bg="#98c379", fg="#ffffff", relief="flat", command=self.decrypt_file
        )
        self.decrypt_button.pack(pady=10, fill="x")

        # Status Label
        self.status_label = Label(master, text="", font=("Helvetica", 10), bg="#282c34", fg="#abb2bf")
        self.status_label.pack(pady=10)

#Botonera encriptado
    def encrypt_file(self):
        file_path = filedialog.askopenfilename(title="Seleccionar archivo para encriptar")
        if file_path:
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Por favor, ingresa una contraseña.")
                return
            
            encryptor = AESFileEncryptor(password)
            output_file = file_path + ".enc"
            success = encryptor.encrypt(file_path, output_file)
            if success:
                messagebox.showinfo("Éxito", f"Archivo encriptado: {output_file}")
                self.status_label.config(text="Archivo encriptado correctamente")

#Botonera desencriptado
    def decrypt_file(self):
        file_path = filedialog.askopenfilename(title="Seleccionar archivo para desencriptar")
        if file_path:
            password = self.password_entry.get()
            if not password:
                messagebox.showerror("Error", "Por favor, ingresa una contraseña.")
                return
            
            encryptor = AESFileEncryptor(password)

            # Generar el nombre del archivo desencriptado
            directory, filename = os.path.split(file_path)
            name, extension = os.path.splitext(filename)

            if extension == ".enc":
                name, original_extension = os.path.splitext(name)
                output_file = os.path.join(directory, f"_desencriptado_{name}{original_extension}")
            else:
                output_file = os.path.join(directory, f"_desencriptado_{name}{extension}")

            # Intentar desencriptar
            success = encryptor.decrypt(file_path, output_file)
            if success:
                messagebox.showinfo("Éxito", f"Archivo desencriptado guardado como: {output_file}")
                self.status_label.config(text="Archivo desencriptado correctamente")


if __name__ == "__main__":
    root = Tk()
    app = AESFileEncryptorApp(root)
    root.mainloop()
