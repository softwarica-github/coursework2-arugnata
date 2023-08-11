from tkinter import *
import tkinter.filedialog
from PIL import ImageTk, Image, ImageDraw
from tkinter import messagebox
import os
import sqlite3
import tkinter as tk
from tkinter import filedialog, messagebox
import cv2
import numpy as np
import json
from random import choice
import qrcode
import hmac
import hashlib
import zlib
from cryptography.fernet import Fernet
import datetime
import qrcode
import tkinter as tk
from tkinter import filedialog
from PIL import Image
import cv2

class Stegno:
    def __init__(self):       
        self.root = Tk()
        self.frame2_decode_window = None
        self.frame2_encode_window = None
        self.decoded_image_path = None
        self.panelA = None
        self.panelB = None
        self.image_path = None
        self.share1_path = None
        self.share2_path = None
        self.shares_paths = []    
        self.selected_image = None
        self.encryption_key = Fernet.generate_key()
        self.image_label = None
        self.start_time = datetime.datetime.now()
        self.log_file = open("log.txt", "a")

        self.conn = sqlite3.connect("encoded_images.db")
        self.cursor = self.conn.cursor()
        self.cursor.execute("CREATE TABLE IF NOT EXISTS encoded_images (id INTEGER PRIMARY KEY AUTOINCREMENT, image BLOB)")

    def log(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {message}\n"
        self.log_file.write(log_entry)
        self.log_file.flush()

    def main(self):
        self.root.title('ImageCryptography')
        self.root.geometry('1250x750')
        self.root.resizable(width=False, height=False)

        bg_color = '#000080'  
        
        self.root.configure(bg=bg_color)

        self.root.configure(borderwidth=0.5, relief="solid",bg='white')

        f = Frame(self.root, bg=bg_color)

        alpha = "ABCDEFGHIJKLMNOPQRSTUVWZYZabcdefghijklmnopqrstuvwxyz0123456789-!@#$%^&*()+"

        def encrypt_text():
            str_input = input_text.get()
            shift1 = int(shift1_input.get())
            shift2 = int(shift2_input.get())
            length = len(str_input)
            str_output = ""
            for i in range(length):
                char = str_input[i]
                location = alpha.find(char)
                new_location1 = (location + shift1) % 66
                new_location2 = (new_location1 + shift2) % 66
                str_output = str_output + alpha[new_location2]
            
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - Encrypted Text: {str_output}\n"
            print("Text encrypted at:", timestamp)
            self.log_file.write(log_entry)
            self.log_file.flush()
            output_text.set(str_output)
            
        def decrypt_text():
            str_input = decrypt_input.get()
            shift1 = int(shift1_input.get())
            shift2 = int(shift2_input.get())
            length = len(str_input)
            str_output = ""
            for i in range(length):
                char = str_input[i]
                location = alpha.find(char)
                new_location2 = (location - shift2) % 66
                new_location1 = (new_location2 - shift1) % 66
                str_output = str_output + alpha[new_location1]
            decrypt_output.set(str_output)

            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"{timestamp} - Decrypted Text: {str_output}\n"
            print("Text decrypted at:", timestamp)
            self.log_file.write(log_entry)
            self.log_file.flush()
            output_text.set(str_output)

        def copy_text():
            self.root.clipboard_clear()
            self.root.clipboard_append(output_text.get())
            self.log("Copied text to clipboard.")

        def paste_text():
            clipboard_text = self.root.clipboard_get()
            decrypt_input.delete(0, END)
            decrypt_input.insert(0, clipboard_text)
            self.log("Pasted text from clipboard.")

        def analyze_image():
            selected_image = tkinter.filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.jpeg;*.jpg")])
            if selected_image:
                if self.is_encoded(selected_image):
                    messagebox.showinfo("Analysis Result", "The image is encoded.")
                    self.log("Image analyzed: The image is encoded.")
                else:
                    messagebox.showinfo("Analysis Result", "The image is not encoded.")
                    self.log("Image analyzed: The image is not encoded.")
            else:
                messagebox.showerror("Error", "No image selected.")
                self.log("Image analysis error: No image selected.")

        def store_image():
            if self.decoded_image_path:
                store_path = tkinter.filedialog.asksaveasfilename(defaultextension=".png")
                if store_path:
                    with open(self.decoded_image_path, "rb") as f:
                        image_data = f.read()

                    self.cursor.execute("INSERT INTO encoded_images (image) VALUES (?)", (image_data,))
                    self.conn.commit()

                    os.rename(self.decoded_image_path, store_path)
                    messagebox.showinfo("Success", "Image stored successfully.")
                    self.log("Image stored successfully.")
                else:
                    messagebox.showerror("Error", "Invalid store path.")
                    self.log("Image store error: Invalid store path.")
            else:
                messagebox.showerror("Error", "No image to store.")
                self.log("Image store error: No image to store.")

        def view_stored_images():
            self.cursor.execute("SELECT image FROM encoded_images")
            encoded_images = self.cursor.fetchall()

            temp_dir = "stored_images_temp"
            if not os.path.exists(temp_dir):
                os.makedirs(temp_dir)

            for i, encoded_image in enumerate(encoded_images):
                image_path = os.path.join(temp_dir, f"encoded_image_{i}.png")
                with open(image_path, "wb") as f:
                    f.write(encoded_image[0])

            os.system(f'explorer "{temp_dir}"')
            self.log("Viewed stored images.")


        title = Label(text='Image Protection with Advanced Cryptographic Techniques', font=('Courier', 27, 'bold'),bg='white',fg='#000080')
        title.pack(pady=5, anchor='center')

        line_canvas = Canvas(f, width=10, height=560, bg='white')
        line_canvas.grid(row=0, column=4, rowspan=10, padx=(20, 0))

        line_canvas = Canvas(f, width=329, height=10, bg='white')
        line_canvas.grid(row=4, column=5,  padx=0, sticky='w')  

        input_label = Label(f, text="Enter a value:", font=('Courier',19),bg=bg_color,fg="#FFFFFA")
        input_label.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        input_text = Entry(f, font=('Courier', 16), borderwidth=8)
        input_text.grid(row=1, column=1, padx=15, pady=5, sticky='w')

        shift1_label = Label(f, text="Enter first value to shift by:", font=('Courier', 19),fg="#FFFFFA",bg=bg_color)
        shift1_label.grid(row=2, column=0, padx=10, pady=5, sticky='w')
        shift1_input = Entry(f, font=('Courier', 16), borderwidth=8)
        shift1_input.grid(row=2, column=1, padx=15, pady=5, sticky='w')

        shift2_label = Label(f, text="Enter second value to shift by:", font=('Courier', 19),   borderwidth=0, relief="flat", bg=bg_color,fg="#FFFFFA")
        shift2_label.grid(row=3, column=0, padx=10, pady=5, sticky='w')
        shift2_input = Entry(f, show="*", font=('Courier', 16), borderwidth=8)
        shift2_input.grid(row=3, column=1, padx=15, pady=5, sticky='w')

        encrypt_button = Button(f, text="Encrypt", command=encrypt_text, font=('Courier', 14))
        encrypt_button.grid(row=4, column=0, columnspan=1, pady=10, sticky='e')

        output_label = Label(f, text="Encrypted text:", font=('Courier', 18),bg=bg_color,fg="#FDFDF5")
        output_label.grid(row=5, column=0, padx=15, pady=5, sticky='w')
        output_text = StringVar()
        output_entry = Entry(f, textvariable=output_text, font=('Courier', 16), borderwidth=8)
        output_entry.grid(row=5, column=1, padx=15, pady=5, sticky='w')

        copy_button = Button(f, text="Copy", command=copy_text, font=('Courier', 14))
        copy_button.grid(row=4, column=1, padx=15, pady=10, sticky='e')

        decrypt_label = Label(f, text="Enter encrypted text to decrypt:", font=('Courier', 19),bg=bg_color,fg="#F5F5FF")
        decrypt_label.grid(row=6, column=0, padx=10, pady=10, sticky='w')
        decrypt_input = Entry(f, font=('Courier', 16), borderwidth=8)
        decrypt_input.grid(row=6, column=1, padx=15, pady=5, sticky='w')
        
        paste_button = Button(f, text="Paste", command=paste_text, font=('Courier', 14))
        paste_button.grid(row=7, column=0, padx=15, pady=5, sticky='e')
        
        decrypt_button = Button(f, text="Decrypt", command=decrypt_text, font=('Courier', 14))
        decrypt_button.grid(row=7, column=1, columnspan=1, padx=10, pady=10, sticky='e')

        decrypt_output_label = Label(f, text="Decrypted text:", font=('Courier', 19),bg=bg_color, fg="#F5F5FF")
        decrypt_output_label.grid(row=8, column=0, padx=10, pady=10, sticky='w')
        decrypt_output = StringVar()
        decrypt_output_entry = Entry(f, textvariable=decrypt_output, font=('Courier', 16), borderwidth=8)
        decrypt_output_entry.grid(row=8, column=1, columnspan=2, padx=10, pady=5, sticky='w')

        b_encode = Button(f, text="Encode", command=self.frame1_encode, padx=14, font=('Courier', 16))
        b_encode.grid(row=1, column=5, padx=20, pady=10, sticky='w')

        b_decode = Button(f, text="Decode", command=self.frame1_decode, padx=14, font=('Courier', 16))
        b_decode.grid(row=1, column=5, padx=20, pady=10, sticky='e')

        b_store = Button(f, text="Store", command=store_image, padx=14, font=('Courier', 16))
        b_store.grid(row=2, column=5, padx=20, pady=10, sticky='e')

        b_analyze = Button(f, text="Analyze", command=analyze_image, padx=14, font=('Courier', 16))
        b_analyze.grid(row=2, column=5, padx=20, pady=10, sticky='w')

        b_view_stored = Button(f, text="View store images", command=view_stored_images, padx=14, font=('Courier', 16))
        b_view_stored.grid(row=3, column=5, padx=20, pady=10, sticky='w')

        visual_button = tk.Button(f, text="Visual-Cryptography", command=self.start_button_click,padx=14, font=('Courier', 16) )
        visual_button.grid(row=5, column=5, padx=20, pady=10, sticky='w')

        encdec_button = tk.Button(f, text="Img-Encrypt/Decrypt", command=self.open_options_window,padx=14, font=('Courier', 16))
        encdec_button.grid(row=6, column=5, padx=20, pady=10, sticky='w')

        encdec_button = tk.Button(f, text="compress/decompress", command=self.show_options_window,padx=14, font=('Courier', 16))
        encdec_button.grid(row=8, column=5, padx=20, pady=10, sticky='w')

        encdec_button = tk.Button(f, text="Hide-Image-In-Image", command=self.open_image_hider_app,padx=14, font=('Courier', 16))
        encdec_button.grid(row=7, column=5, padx=20, pady=10, sticky='w')
       
        f.pack(padx=20, pady=20)
        self.root.mainloop()
    
    def home(self):
        pass

    def show_options_window(self):
        self.log("Opening Image Hiding App options window.")
        self.options_window = tk.Toplevel(self.root)
        self.options_window.title("Image Hiding App")
       
        open_button = tk.Button(self.options_window, text="Open Image", command=self.open_image)
        open_button.pack(pady=10)

        self.image_label = tk.Label(self.options_window)
        self.image_label.pack(pady=10)

        encrypt_compress_button = tk.Button(self.options_window, text="Encrypt and Compress", command=self.encrypt_compress_image)
        encrypt_compress_button.pack(pady=10)

        decrypt_decompress_button = tk.Button(self.options_window, text="Decrypt and Decompress", command=self.decrypt_decompress_image)
        decrypt_decompress_button.pack(pady=10)

        check_metadata_button = tk.Button(self.options_window, text="Check Metadata", command=self.check_metadata)
        check_metadata_button.pack(pady=10)

    def compress_data(self, data):
        self.log("Compressing data.")
        compressed_data = zlib.compress(data)
        return compressed_data
        
    def decompress_data(self, compressed_data):
        self.log("Decompressing data.")
        decompressed_data = zlib.decompress(compressed_data)
        return decompressed_data

    def encrypt_data(self, data, key):
        self.log("Encrypting data.")
        f = Fernet(key)
        encrypted_data = f.encrypt(data)
        return encrypted_data

    def decrypt_data(self, encrypted_data, key):
        self.log("Decrypting data.")
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return decrypted_data

    def open_image(self):
        self.log("Opening image.")
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.png;*.jpeg")])
        if file_path:
            original_image = Image.open(file_path)
            original_image.thumbnail((300, 300))
            photo = ImageTk.PhotoImage(original_image)
            self.image_label.config(image=photo)
            self.image_label.image = photo
            self.selected_image = file_path

    def encrypt_compress_image(self):
        self.log("Encrypting and compressing image.")
        if not self.selected_image:
            return
    
        with open(self.selected_image, "rb") as f:
            data = f.read()

        encrypted_data = self.encrypt_data(data, self.encryption_key)
        compressed_data = self.compress_data(encrypted_data)

        encrypted_image_path = filedialog.asksaveasfilename(defaultextension=".enc",
                                                        filetypes=[("Encrypted Image", "*.enc")])
        if encrypted_image_path:
            with open(encrypted_image_path, "wb") as f:
                f.write(b"COMPRESSED_ENCRYPTED_IMAGE") 
                f.write(compressed_data)

            messagebox.showinfo("Success", "Image successfully encrypted and compressed.")

    def decrypt_decompress_image(self):
        self.log("Decrypting and decompressing image.")
        encrypted_image_path = filedialog.askopenfilename(filetypes=[("Encrypted Image", "*.enc")])
        if encrypted_image_path:
            with open(encrypted_image_path, "rb") as f:
                metadata = f.read(26)  

                if metadata == b"COMPRESSED_ENCRYPTED_IMAGE":
                    compressed_data = f.read()

                    decrypted_data = self.decompress_data(compressed_data)
                    decrypted_data = self.decrypt_data(decrypted_data, self.encryption_key)

                    decompressed_image_path = filedialog.asksaveasfilename(defaultextension=".jpg",
                                                                      filetypes=[("Image", "*.jpg")])
                    if decompressed_image_path:
                        with open(decompressed_image_path, "wb") as f:
                            f.write(decrypted_data)

                        messagebox.showinfo("Success", "Image successfully decompressed and decrypted.")
                    else:
                        messagebox.showerror("Error", "Invalid or unprocessed file format.")
                else:
                    messagebox.showerror("Error", "Invalid or unprocessed file format.")


    def check_metadata(self):
        self.log("Checking metadata.")
        encrypted_image_path = filedialog.askopenfilename(filetypes=[("Encrypted Image", "*.enc")])
        if encrypted_image_path:
            with open(encrypted_image_path, "rb") as f:
                metadata = f.read(26)  

                if metadata == b"COMPRESSED_ENCRYPTED_IMAGE":
                    messagebox.showinfo("Metadata Check", "The image is compressed and encrypted.")
                else:
                    messagebox.showinfo("Metadata Check", "The image is not compressed and encrypted.")


    def open_image_hider_app(self):
            
        self.log("Opening Image Hiding App.")
        self.image_hider_window = tk.Toplevel(self.root)
        self.image_hider_window.title("Image Hiding App")
        self.cover_path = ""
        self.secret_path = ""
        self.stego_path = ""
        self.cover_image = None
        self.secret_image = None
        self.stego_image = None
        self.secret_extracted_image = None
        self.step = 1
        self.create_widgets()

    def create_widgets(self):
        
        self.label = tk.Label(self.image_hider_window, text="Select the action:", font=("Arial", 20))
        self.label.pack(pady=15)

        self.buttons_frame = tk.Frame(self.image_hider_window)
        self.buttons_frame.pack(side=tk.LEFT, padx=10)

        self.images_frame = tk.Frame(self.image_hider_window)
        self.images_frame.pack(side=tk.LEFT, padx=10)

        self.select_cover_button = tk.Button(self.buttons_frame, text="Select Cover Image", command=self.select_cover_image, font=("Arial", 16, 'bold'),bg='grey', fg="white", borderwidth=5)
        self.select_cover_button.pack(pady=5, padx=5, fill=tk.X)

        self.select_secret_button = tk.Button(self.buttons_frame, text="Select Secret Image", fg='white',command=self.select_secret_image, font=("Arial", 16, 'bold'),bg='grey', borderwidth=5)
        self.select_secret_button.pack(pady=5, padx=5, fill=tk.X)

        self.hide_button = tk.Button(self.buttons_frame, text="Hide Secret Image", command=self.hide_secret_image, font=("Arial", 16, 'bold'), fg="white",bg='grey',borderwidth=5)
        self.hide_button.pack(pady=5, padx=5, fill=tk.X)

        self.extract_button = tk.Button(self.buttons_frame, text="Extract Hidden Image", command=self.extract_hidden_image, font=("Arial", 16,'bold'),bg='grey', fg="white", borderwidth=5)
        self.extract_button.pack(pady=5, padx=5, fill=tk.X)

        self.load_stego_button = tk.Button(self.buttons_frame, text="Load Stego Image", command=self.load_stego_image, font=("Arial", 16, 'bold'), bg='grey', fg="white", borderwidth=5)
        self.load_stego_button.pack(pady=5, padx=5, fill=tk.X)

    def select_cover_image(self):
        self.log("Selecting cover image.")
        self.cover_path = filedialog.askopenfilename(title="Select the cover image", filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
        
        if self.cover_path:
            self.cover_image = Image.open(self.cover_path).convert("RGB")
            self.show_image(self.cover_image, self.images_frame)
            self.select_secret_button.config(state=tk.NORMAL)
            self.label.config(text="Select the secret image")
            self.step = 2

    def select_secret_image(self):
        self.log("Selecting secret image.")
        if self.step < 2:
            self.show_error("Please complete the previous step first.")
            return

        self.secret_path = filedialog.askopenfilename(title="Select the secret image", filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
        if self.secret_path:
            self.secret_image = Image.open(self.secret_path).convert("RGB")
            self.show_image(self.secret_image, self.images_frame)
            self.hide_button.config(state=tk.NORMAL)
            self.label.config(text="Hide the secret image")
            self.step = 3

    def hide_secret_image(self):
        self.log("Hiding secret image.")
        if self.step < 3:
            self.show_error("Please complete the previous step first.")
            return

        if self.cover_image and self.secret_image:        
            self.secret_image = self.secret_image.resize(self.cover_image.size)

            cover_pixels = self.cover_image.load()
            secret_pixels = self.secret_image.load()

            for i in range(self.cover_image.size[0]):
                for j in range(self.cover_image.size[1]):
                    r, g, b = cover_pixels[i, j]
                    sr, sg, sb = secret_pixels[i, j]

                    r = (r & 254) | ((sr >> 7) & 1)
                    g = (g & 254) | ((sg >> 7) & 1)
                    b = (b & 254) | ((sb >> 7) & 1)

                    cover_pixels[i, j] = (r, g, b)

            self.stego_path = filedialog.asksaveasfilename(title="Save the stego image", filetypes=[("Image files", "*.png")])
            if self.stego_path:
                self.cover_image.save(self.stego_path)
                self.stego_image = Image.open(self.stego_path).convert("RGB")
                self.show_image(self.stego_image, self.images_frame)
                self.extract_button.config(state=tk.NORMAL)
                self.label.config(text="Extract the hidden image")
                self.step = 4

    def extract_hidden_image(self):
        self.log("Extracting hidden image.")
        if self.step < 4:
            self.show_error("Please complete the previous step first.")
            return

        if self.stego_image:
            # Extract the secret image using LSB steganography
            stego_pixels = self.stego_image.load()
            self.secret_extracted_image = Image.new("RGB", self.stego_image.size)
            secret_extracted_pixels = self.secret_extracted_image.load()

            for i in range(self.stego_image.size[0]):
                for j in range(self.stego_image.size[1]):
                    r, g, b = stego_pixels[i, j]

                    # Extract the least significant bit of each color channel to get secret image pixels
                    sr = (r & 1) << 7
                    sg = (g & 1) << 7
                    sb = (b & 1) << 7

                    secret_extracted_pixels[i, j] = (sr, sg, sb)

            self.show_image(self.secret_extracted_image, self.images_frame)

    def load_stego_image(self):
        self.log("Loading stego image.")
        self.stego_path = filedialog.askopenfilename(title="Load the stego image", filetypes=[("Image files", "*.png")])
        if self.stego_path:
            self.stego_image = Image.open(self.stego_path).convert("RGB")
            self.show_image(self.stego_image, self.images_frame)
            self.extract_button.config(state=tk.NORMAL)
            self.label.config(text="Extract the hidden image")
            self.step = 4

    def show_image(self, image, frame):
        if hasattr(self, "image_window"):
            self.image_window.destroy()

        self.image_window = tk.Toplevel(self.image_hider_window)
        self.image_window.title("Image Preview")

        img_tk = ImageTk.PhotoImage(image)
        image_label = tk.Label(self.image_window, image=img_tk)
        image_label.image = img_tk
        image_label.pack(pady=10)

    def show_error(self, message):
        messagebox.showerror("Error", message)


    def open_options_window(self):
        self.log("starting Image Encryption Decryption")
        
        options_window = tk.Toplevel(self.root)
        options_window.geometry("1100x700")
        options_window.title("Image Encryption Decryption")
        options_window.config(bg='black')
           
        line_canvas = Canvas(options_window, width=4, height=1180, bg='white')
        line_canvas.pack(fill=tk.Y)
        line_canvas.place(relx=0.5, anchor=tk.CENTER)
        
        line_canvas = Canvas(options_window, width=6, height=110, bg='white')
        line_canvas.pack(side=tk.BOTTOM, fill=tk.X)

        line_canvas = Canvas(options_window, width=6, height=100, bg='white')
        line_canvas.pack(side=tk.TOP, fill=tk.X)

        global panelA, panelB, x, eimg, key

        panelA = None
        panelB = None
        x = None
        eimg = None
        key = None

        def getpath(path):
            a = path.split(r'/')
            fname = a[-1]
            l = len(fname)
            location = path[:-l]
            return location

        def getfilename(path):
            a = path.split(r'/')
            fname = a[-1]
            a = fname.split('.')
            a = a[0]
            return a

        def openfilename():
            filename = filedialog.askopenfilename(title='Open')
            return filename

        def open_img():
            global x, panelA, panelB, eimg
            x = openfilename()
            if not x:
                return

            img = Image.open(x)
            eimg = img.copy()
            img = ImageTk.PhotoImage(img)

            if panelA is None or panelB is None:
                panelA = tk.Label(options_window, image=img)
                panelA.image = img
                panelA.pack(side="left", padx=10, pady=10)
                panelB = tk.Label(options_window, image=img)
                panelB.image = img
                panelB.pack(side="right", padx=10, pady=10)
            else:
                panelA.configure(image=img)
                panelB.configure(image=img)
                panelA.image = img
                panelB.image = img

        def en_fun():
            
            global x, eimg, key

            if x is None:
                messagebox.showerror("Error", "Please select an image first.")
                return

            key_entry_window = tk.Toplevel(options_window)
            key_entry_window.title("Enter Encryption Key")
            key_entry_window.geometry("300x100")
            key_entry_label = tk.Label(key_entry_window, text="Enter the encryption key:")
            key_entry_label.pack()
            key_entry = tk.Entry(key_entry_window, show="*")
            key_entry.pack()

            def encrypt_image():
                global key

                entered_key = key_entry.get()

                if not entered_key.strip().isdigit():
                    messagebox.showerror("Error", "Please enter a valid encryption key (numeric).")
                    return

                key = int(entered_key)

                image_input = cv2.imread(x, 0)
                (x1, y) = image_input.shape
                image_input = image_input.astype(float) / 255.0

                key = np.full((x1, y), key) + np.finfo(float).eps
                image_encrypted = image_input / key
                cv2.imwrite('image_encrypted.jpg', image_encrypted * 255)

                with open('encryption_key.json', 'w') as f:
                    json.dump({"key": key.tolist()}, f)

                imge = Image.open('image_encrypted.jpg')
                imge = ImageTk.PhotoImage(imge)
                panelB.configure(image=imge)
                panelB.image = imge
                messagebox.showinfo("Encrypt Status", "Image Encrypted successfully.")
                self.log("Encrypt Status", "Image Encrypted successfully")
                key_entry_window.destroy()

            encrypt_button = tk.Button(key_entry_window, text="Encrypt", command=encrypt_image)
            encrypt_button.pack()

        def de_fun():
            global x, eimg, decryption_key

            if x is None:
                messagebox.showerror("Error", "Please select an image first.")
                return

            key_entry_window = tk.Toplevel(options_window)
            key_entry_window.title("Enter Decryption Key")
            key_entry_window.geometry("300x100")
            key_entry_label = tk.Label(key_entry_window, text="Enter the decryption key:")
            key_entry_label.pack()
            key_entry = tk.Entry(key_entry_window, show="*")
            key_entry.pack()

            def decrypt_image():
                global decryption_key

                entered_key = key_entry.get()

                if not entered_key.strip().isdigit():
                    messagebox.showerror("Error", "Please enter a valid decryption key (numeric).")
                    return

                decryption_key = int(entered_key)

                with open('encryption_key.json', 'r') as f:
                    data = json.load(f)
                    key = np.array(data["key"])

                if decryption_key == key[0][0]:
                    image_encrypted = cv2.imread('image_encrypted.jpg', 0)
                    image_output = image_encrypted * key
                    image_output *= 255.0
                    cv2.imwrite('image_output.jpg', image_output)

                    imgd = Image.open('image_output.jpg')
                    imgd = ImageTk.PhotoImage(imgd)
                    panelB.configure(image=imgd)
                    panelB.image = imgd
                    messagebox.showinfo("Decrypt Status", "Image Decrypted successfully.")
                    self.log("Image Decrypted successfully")

                    decrypted_img = Image.fromarray(image_output.astype(np.uint8))
                    filename = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG Image", "*.jpg")])
                    if filename:
                        decrypted_img.save(filename)
                        messagebox.showinfo("Success", "Decrypted Image Saved Successfully!")
                        self.log("Decrypted Image Saved Successfully")

                    key_entry_window.destroy()
                else:
                    messagebox.showerror("Error", "Incorrect decryption key.")

            decrypt_button = tk.Button(key_entry_window, text="Decrypt", command=decrypt_image)
            decrypt_button.pack()

        def reset():
            global x, eimg

            if x is None:
                messagebox.showerror("Error", "Please select an image first.")
                return

            eimg = Image.open(x)
            img = ImageTk.PhotoImage(eimg)

            panelB.configure(image=img)
            panelB.image = img
            messagebox.showinfo("Success", "Image reset to the original format!")
            self.log("Image reset to the original format")

        def save_img():
            global eimg, key

            if x is None:
                messagebox.showerror("Error", "No image to save.")
                return

            if key is None:
                filename = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG Image", "*.jpg")])
                if filename:
                    eimg.save(filename)
                    messagebox.showinfo("Success", "Original Image Saved Successfully!")
                    self.log("Original Image Saved Successfully")
            else:
                filename = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG Image", "*.jpg")])
                if filename:
                    encrypted_img = Image.open('image_encrypted.jpg')
                    encrypted_img.save(filename)
                    messagebox.showinfo("Success", "Encrypted Image Saved Successfully!")
                    self.log("Encrypted Image Saved Successfully")

        def exit_win():
            if messagebox.askokcancel("Exit", "Do you want to exit?"):
                options_window.destroy()


        start1 = tk.Label(options_window, text="Image Encryption Decryption ", font=("Arial", 20,'bold'), fg="black",background='white')
        start1.place(x=350, y=1)

        start1 = tk.Label(options_window, text="Original Image", font=("Arial", 20), fg="black",background='white')
        start1.place(x=100, y=50)

        start1 = tk.Label(options_window, text="Encrypted & Decrypted Image", font=("Arial", 20), fg="black", background='white')
        start1.place(x=700, y=50)

        chooseb = tk.Button(options_window, text="Choose", command=open_img, font=("Arial", 20), bg="orange", fg="blue", borderwidth=3, relief="raised")
        chooseb.place(x=80, y=600)

        saveb = tk.Button(options_window, text="Save", command=save_img, font=("Arial", 20), bg="orange", fg="blue", borderwidth=3, relief="raised")
        saveb.place(x=700, y=600)

        enb = tk.Button(options_window, text="Encrypt", command=en_fun, font=("Arial", 20), bg="light green", fg="blue", borderwidth=3, relief="raised")
        enb.place(x=250, y=600)

        deb = tk.Button(options_window, text="Decrypt", command=de_fun, font=("Arial", 20), bg="orange", fg="blue", borderwidth=3, relief="raised")
        deb.place(x=400, y=600)

        resetb = tk.Button(options_window, text="Reset", command=reset, font=("Arial", 20), bg="yellow", fg="blue", borderwidth=3, relief="raised")
        resetb.place(x=550, y=600)

        exitb = tk.Button(options_window, text="EXIT", command=exit_win, font=("Arial", 20), bg="red", fg="blue", borderwidth=3, relief="raised")
        exitb.place(x=880, y=600)

        options_window.protocol("WM_DELETE_WINDOW", exit_win)
        options_window.mainloop()

    
    def open_img(self):
        self.log("starting visual cryptography")
    
        self.image_path = filedialog.askopenfilename(title='Open')
        if not self.image_path:
            return

        img = Image.open(self.image_path)
        img = img.resize((500, 500))
        img_tk = ImageTk.PhotoImage(img)

        new_window = tk.Toplevel(self.root)
        new_window.title("Image Viewer")
        
        new_window.geometry("500x500")  # Adjust the size if needed
        title_label = tk.Label(new_window, text="Original image", font=("Arial", 16, "bold"))
        title_label.pack(pady=10)

        panel = tk.Label(new_window, image=img_tk)
        panel.image = img_tk
        panel.pack()

  
    def generate_qr_code(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if file_path:
            qr = qrcode.QRCode(version=1, box_size=10, border=5)
            qr.add_data(file_path)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            img.save("generated_qr.png")
            img.show()

    def decrypt_qr_code(self):
        file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp")])
        if file_path:
            image = cv2.imread(file_path)
            qr_decoder = cv2.QRCodeDetector()
            decoded_info, _, _ = qr_decoder.detectAndDecode(image)
            if decoded_info:
                qr_data = decoded_info
                decrypted_image = Image.open(qr_data)
                decrypted_image.show()
            else:
                print("No QR Code found in the selected image.")

    def create_shares(self):
        self.log("Creating shares.")
        if self.image_path is None:
            messagebox.showerror("Error", "Please select an image first.")
            return

        img = Image.open(self.image_path).convert('1')
       
        width, height = img.size
        out_image_A = Image.new('1', (width * 2, height * 2))
        out_image_B = Image.new('1', (width * 2, height * 2))
        draw_A = ImageDraw.Draw(out_image_A)
        draw_B = ImageDraw.Draw(out_image_B)
        
        patterns = [(1, 1, 0, 0), (1, 0, 1, 0), (1, 0, 0, 1), (0, 1, 1, 0), (0, 1, 0, 1), (0, 0, 1, 1)]
       
        for x in range(width):
            for y in range(height):
                pixel = img.getpixel((x, y))
                pat = choice(patterns)
               
                draw_A.point((x * 2, y * 2), pat[0])
                draw_A.point((x * 2 + 1, y * 2), pat[1])
                draw_A.point((x * 2, y * 2 + 1), pat[2])
                draw_A.point((x * 2 + 1, y * 2 + 1), pat[3])
               
                if pixel == 0:
                    draw_B.point((x * 2, y * 2), 1 - pat[0])
                    draw_B.point((x * 2 + 1, y * 2), 1 - pat[1])
                    draw_B.point((x * 2, y * 2 + 1), 1 - pat[2])
                    draw_B.point((x * 2 + 1, y * 2 + 1), 1 - pat[3])
                else:
                    draw_B.point((x * 2, y * 2), pat[0])
                    draw_B.point((x * 2 + 1, y * 2), pat[1])
                    draw_B.point((x * 2, y * 2 + 1), pat[2])
                    draw_B.point((x * 2 + 1, y * 2 + 1), pat[3])

     
        share1_filename = self.image_path[:-4] + "_share1.png"
        share2_filename = self.image_path[:-4] + "_share2.png"
        out_image_A.save(share1_filename, 'PNG')
        out_image_B.save(share2_filename, 'PNG')
      
        self.add_digital_signature(share1_filename)
        self.add_digital_signature(share2_filename)
        self.shares_paths = [share1_filename, share2_filename]       
        self.generate_and_save_qr_codes(self.shares_paths)
        messagebox.showinfo("Share Creation Status", f"Two shares created: {share1_filename} and {share2_filename}")

    def add_digital_signature(self, share_path):
        self.log("Adding digital signature.")
        with open(share_path, 'rb') as file:
            data = file.read()

        signature = hmac.new(b'secret-key', data, hashlib.sha256).digest()
        with open(share_path, 'ab') as file:
            file.write(signature)

    def verify_signature(self, data, signature):
        self.log("Verifying signature.")
        return hmac.compare_digest(signature, hmac.new(b'secret-key', data, hashlib.sha256).digest())

    def verify_digital_signature(self):
        self.log("Verifying digital signature.")
        share1_path = filedialog.askopenfilename(title='Select Share 1 with QR code')
        share2_path = filedialog.askopenfilename(title='Select Share 2 with QR code')

        if not share1_path or not share2_path:
            return

        with open(share1_path, 'rb') as file:
            share1_data = file.read()

        with open(share2_path, 'rb') as file:
            share2_data = file.read()

      
        signature_size = 32
        share1_signature = share1_data[-signature_size:]
        share2_signature = share2_data[-signature_size:]

      
        share1_original = share1_data[:-signature_size]
        share2_original = share2_data[:-signature_size]

        if self.verify_signature(share1_original, share1_signature) and self.verify_signature(share2_original, share2_signature):
            messagebox.showinfo("Verification Status", "Digital signatures are valid. Shares are authentic and not tampered.")
        else:
            messagebox.showerror("Verification Status", "Digital signatures do not match. Shares may have been tampered.")

    def decrypt_shares(self):
        self.log("Decrypting shares.")
        self.share1_path = filedialog.askopenfilename(title='Select Share 1')
        self.share2_path = filedialog.askopenfilename(title='Select Share 2')

        if not self.share1_path or not self.share2_path:
            return

        with open(self.share1_path, 'rb') as file:
            share1_data = file.read()

        with open(self.share2_path, 'rb') as file:
            share2_data = file.read()

        share1_signature = share1_data[-32:]  
        share2_signature = share2_data[-32:]  

        if not self.verify_signature(share1_data[:-32], share1_signature) or not self.verify_signature(share2_data[:-32], share2_signature):
            messagebox.showerror("Error", "Invalid shares or tampering detected. Digital signatures do not match.")
            return

        share1_img = Image.open(self.share1_path).convert('1')
        share2_img = Image.open(self.share2_path).convert('1')

        # Combine the shares using XOR
        width, height = share1_img.size
        decrypted_img = Image.new('1', (width, height))

        pixels_share1 = share1_img.load()
        pixels_share2 = share2_img.load()
        pixels_decrypted = decrypted_img.load()

        for y in range(height):
            for x in range(width):
                pixels_decrypted[x, y] = pixels_share1[x, y] ^ pixels_share2[x, y]

        decrypted_img = decrypted_img.resize((400, 400))
        decrypted_tk_img = ImageTk.PhotoImage(decrypted_img)

        new_window = tk.Toplevel(self.root)
        new_window.title("Decrypted Image")
        
        new_window.geometry("420x420")  

        title_label = tk.Label(new_window, text="Decrypted Share", font=("Arial", 14, "bold"))
        title_label.pack(pady=10)

        panel = tk.Label(new_window, image=decrypted_tk_img)
        panel.image = decrypted_tk_img
        panel.pack()

        if self.panelA:
            self.panelA.pack_forget()
            self.panelA = None

      
    def open_save_combined_image_window(self):
        self.log("Opening save combined image window.")
        start_window = tk.Toplevel(self.root)
        start_window.title("Save Combined Image")
        start_window.geometry("300x100")

        save_combined_button = tk.Button(start_window, text="Save Combined Image", command=self.save_combined_image)
        save_combined_button.pack(pady=10)

    def save_combined_image(self):
        self.log("Saving combined image.")
        if self.share1_path is None or self.share2_path is None:
            messagebox.showerror("Error", "Please select both shares first.")
            return

        share1_img = Image.open(self.share1_path).convert('1')
        share2_img = Image.open(self.share2_path).convert('1')

        width, height = share1_img.size
        combined_img = Image.new('1', (width * 2, height))

        pixels_share1 = share1_img.load()
        pixels_share2 = share2_img.load()
        pixels_combined = combined_img.load()

        for y in range(height):
            for x in range(width):
                pixels_combined[x * 2, y] = pixels_share1[x, y]
                pixels_combined[x * 2 + 1, y] = pixels_share2[x, y]

        combined_img_path = filedialog.asksaveasfilename(title='Save Combined Image', filetypes=(("PNG Files", "*.png"), ("All Files", "*.*")))

        if combined_img_path:
            combined_img.save(combined_img_path, 'PNG')
            messagebox.showinfo("Save Status", "Combined image saved successfully.")

    def start_button_click(self):
        self.log("Start button clicked.")
        start_window = tk.Toplevel(self.root)
        start_window.title("Visualcrypto")
        start_window.geometry("550x700")
        start_window.config(bg='black', pady=40)

        title = tk.Label(start_window, text="Image Visual Cryptography ", font=("Arial", 20,'bold'), fg="white",background='black')
        title.pack(pady=10)

        open_button = tk.Button(start_window, text="Choose Image", command=self.open_img,font=("Arial", 18), fg="blue", borderwidth=5)
        open_button.pack(pady=10)

        generate_qr_button = tk.Button(start_window, text="Generate QR Code", command=self.generate_qr_code,font=("Arial", 18), fg="blue", borderwidth=5)
        decrypt_qr_button = tk.Button(start_window, text="Decrypt QR Code", command=self.decrypt_qr_code,font=("Arial", 18), fg="blue", borderwidth=5)

        generate_qr_button.pack(pady=20)
        decrypt_qr_button.pack(pady=10)

        encrypt_button = tk.Button(start_window, text="Encrypt and Generate Shares", command=self.create_shares,font=("Arial", 18), fg="blue", borderwidth=5)
        encrypt_button.pack(pady=10)

        decrypt_button = tk.Button(start_window, text="Decrypt Shares", command=self.decrypt_shares,font=("Arial", 18), fg="blue", borderwidth=5)
        decrypt_button.pack(pady=10)

        verify_button = tk.Button(start_window, text="Verify Digital Signatures", command=self.verify_digital_signature,font=("Arial", 18), fg="blue", borderwidth=5)
        verify_button.pack(pady=10)

        save_combined_button = tk.Button(start_window, text="Save Combined Image", command=self.open_save_combined_image_window,font=("Arial", 18),  fg="blue", borderwidth=5)
        save_combined_button.pack(pady=10)


    def frame1_decode(self):
        if self.frame2_decode_window:
            self.frame2_decode_window.destroy()  
        self.root.withdraw()
        d_f2 = Toplevel(self.root)
        d_f2.title('Decode')
        

        ascii_art = """                                                                                                                                          
                                                                                                                                                                      
               AAA                                                                                                                    tttt                            
              A:::A                                                                                                                ttt:::t                            
             A:::::A                                                                                                               t:::::t                            
            A:::::::A                                                                                                              t:::::t                            
           A:::::::::A          rrrrr   rrrrrrrrr   uuuuuu    uuuuuu     ggggggggg   gggggnnnn  nnnnnnnn      aaaaaaaaaaaaa  ttttttt:::::ttttttt      aaaaaaaaaaaaa   
          A:::::A:::::A         r::::rrr:::::::::r  u::::u    u::::u    g:::::::::ggg::::gn:::nn::::::::nn    a::::::::::::a t:::::::::::::::::t      a::::::::::::a  
         A:::::A A:::::A        r:::::::::::::::::r u::::u    u::::u   g:::::::::::::::::gn::::::::::::::nn   aaaaaaaaa:::::at:::::::::::::::::t      aaaaaaaaa:::::a 
        A:::::A   A:::::A       rr::::::rrrrr::::::ru::::u    u::::u  g::::::ggggg::::::ggnn:::::::::::::::n           a::::atttttt:::::::tttttt               a::::a 
       A:::::A     A:::::A       r:::::r     r:::::ru::::u    u::::u  g:::::g     g:::::g   n:::::nnnn:::::n    aaaaaaa:::::a      t:::::t              aaaaaaa:::::a 
      A:::::AAAAAAAAA:::::A      r:::::r     rrrrrrru::::u    u::::u  g:::::g     g:::::g   n::::n    n::::n  aa::::::::::::a      t:::::t            aa::::::::::::a 
     A:::::::::::::::::::::A     r:::::r            u::::u    u::::u  g:::::g     g:::::g   n::::n    n::::n a::::aaaa::::::a      t:::::t           a::::aaaa::::::a 
    A:::::AAAAAAAAAAAAA:::::A    r:::::r            u:::::uuuu:::::u  g::::::g    g:::::g   n::::n    n::::na::::a    a:::::a      t:::::t    tttttta::::a    a:::::a 
   A:::::A             A:::::A   r:::::r            u:::::::::::::::uug:::::::ggggg:::::g   n::::n    n::::na::::a    a:::::a      t::::::tttt:::::ta::::a    a:::::a 
  A:::::A               A:::::A  r:::::r             u:::::::::::::::u g::::::::::::::::g   n::::n    n::::na:::::aaaa::::::a      tt::::::::::::::ta:::::aaaa::::::a 
 A:::::A                 A:::::A r:::::r              uu::::::::uu:::u  gg::::::::::::::g   n::::n    n::::n a::::::::::aa:::a       tt:::::::::::tt a::::::::::aa:::a
AAAAAAA                   AAAAAAArrrrrrr                uuuuuuuu  uuuu    gggggggg::::::g   nnnnnn    nnnnnn  aaaaaaaaaa  aaaa         ttttttttttt    aaaaaaaaaa  aaaa
                                                                                  g:::::g                                                                             
                                                                      gggggg      g:::::g                                                                             
                                                                      g:::::gg   gg:::::g                                                                             
                                                                       g::::::ggg:::::::g                                                                             
                                                                        gg:::::::::::::g                                                                              
                                                                          ggg::::::ggg                                                                                
                                                                             gggggg                                                                                                            
    """

        l1 = Label(d_f2, text=ascii_art, font=('Courier', 2))
        l1.grid()

        l1 = Label(d_f2, text='Select Image with Hidden text:', font=('Courier', 18))
        l1.grid()
        bws_button = Button(d_f2, text='Select', command=lambda: [self.frame2_decode(), d_f2.destroy()],
                            font=('Courier', 18))
        bws_button.grid()
        back_button = Button(d_f2, text='Cancel', command=lambda: [d_f2.destroy(), self.root.deiconify()],
                             font=('Courier', 18))
        back_button.grid(pady=15)
        d_f2.protocol('WM_DELETE_WINDOW', lambda: [d_f2.destroy(), self.root.deiconify()])

    def frame2_decode(self):
        self.log("Frame2 Decode started.")
        if self.frame2_decode_window and self.frame2_decode_window.winfo_exists():
            self.frame2_decode_window.lift()
        else:
            self.frame2_decode_window = Toplevel(self.root)
            self.frame2_decode_window.title('Decode')

            myfile = tkinter.filedialog.askopenfilename(
                filetypes=([("png", ".png"), ("jpeg", ".jpeg"), ("jpg", ".jpg"), ("All Files", ".*")]))
            if not myfile:
                messagebox.showerror("Error", "You have selected nothing !")
            else:
                self.frame2_decode_window.deiconify()
                myimg = Image.open(myfile, 'r')
                myimage = myimg.resize((300, 200))
                img = ImageTk.PhotoImage(myimage)
                l4 = Label(self.frame2_decode_window, text='Selected Image :', font=('Courier', 18))
                l4.grid()
                panel = Label(self.frame2_decode_window, image=img)
                panel.image = img
                panel.grid()
                hidden_data = self.decode(myimg)
                l2 = Label(self.frame2_decode_window, text='Hidden data is :', font=('Courier', 18))
                l2.grid(pady=10)
                text_area = Text(self.frame2_decode_window, width=50, height=10)
                text_area.insert(INSERT, hidden_data)
                text_area.configure(state='disabled')
                text_area.grid()
                back_button = Button(self.frame2_decode_window, text='Cancel',
                                     command=lambda: [self.frame2_decode_window.destroy(), self.root.deiconify()],
                                     font=('Courier', 11))
                back_button.grid(pady=15)
                show_info = Button(self.frame2_decode_window, text='More Info', command=self.info,
                                   font=('Courier', 11))
                show_info.grid()              
                self.decoded_image_path = myfile
                self.frame2_decode_window.protocol('WM_DELETE_WINDOW', lambda: [self.frame2_decode_window.destroy(),
                                                                                 self.root.deiconify()])

    def decode(self, image):
        self.log("Decoding started.")
        data = ''
        imgdata = iter(image.getdata())

        while True:
            pixels = [value for value in imgdata.__next__()[:3] +
                      imgdata.__next__()[:3] +
                      imgdata.__next__()[:3]]
            binstr = ''
            for i in pixels[:8]:
                if i % 2 == 0:
                    binstr += '0'
                else:
                    binstr += '1'

            data += chr(int(binstr, 2))
            if pixels[-1] % 2 != 0:
                return data

    def frame1_encode(self):
        if self.frame2_encode_window:
            self.frame2_encode_window.destroy() 
        self.root.withdraw()
        f2 = Toplevel(self.root)
        f2.title('Encode')

        # ASCII art
        art_label = Label(f2, text=""" 
Arugnata
.===========================.
[   Protect your Data        ]
'==========================='
    """, font=('Courier', 13, 'italic'), fg='green')
        art_label.pack(pady=5)

        l1 = Label(f2, text='Select the Image in which \nyou want to hide text:', font=('Courier', 18))
        l1.pack()

        bws_button = Button(f2, text='Select', command=lambda: [self.frame2_encode(), f2.destroy()],
                            font=('Courier', 18))
        bws_button.pack(pady=10)

        back_button = Button(f2, text='Cancel', command=lambda: [f2.destroy(), self.root.deiconify()],
                             font=('Courier', 18))
        back_button.pack(pady=15)

        f2.protocol('WM_DELETE_WINDOW', lambda: [f2.destroy(), self.root.deiconify()])

    def frame2_encode(self):
        if self.frame2_encode_window and self.frame2_encode_window.winfo_exists():
            self.frame2_encode_window.lift()
        else:
            self.frame2_encode_window = Toplevel(self.root)
            self.frame2_encode_window.title('Encode')
            myfile = tkinter.filedialog.askopenfilename(
                filetypes=([("png", ".png"), ("jpeg", ".jpeg"), ("jpg", ".jpg"), ("All Files", ".*")]))
            if not myfile:
                messagebox.showerror("Error", "You have selected nothing !")
            else:
                myimg = Image.open(myfile)
                myimage = myimg.resize((300, 200))
                img = ImageTk.PhotoImage(myimage)
                l3 = Label(self.frame2_encode_window, text='Selected Image', font=('Courier', 18))
                l3.grid()
                panel = Label(self.frame2_encode_window, image=img)
                panel.image = img
                self.output_image_size = os.stat(myfile)
                self.o_image_w, self.o_image_h = myimg.size
                panel.grid()
                l2 = Label(self.frame2_encode_window, text='Enter the message', font=('Courier', 18))
                l2.grid(pady=15)
                text_area = Text(self.frame2_encode_window, width=50, height=5)
                text_area.grid()
                encode_button = Button(self.frame2_encode_window, text='Cancel',
                                       command=lambda: [self.enc_fun(text_area, myimg),
                                                        self.frame2_encode_window.destroy()],
                                       font=('Courier', 11))
                encode_button.grid()
                back_button = Button(self.frame2_encode_window, text='Encode',
                                     command=lambda: [self.enc_fun(text_area, myimg),
                                                      self.frame2_encode_window.destroy()],
                                     font=('Courier', 11))
                back_button.grid(pady=15)
                self.frame2_encode_window.protocol('WM_DELETE_WINDOW', lambda: [self.frame2_encode_window.destroy(),
                                                                                 self.root.deiconify()])
                self.frame2_encode_window.protocol('WM_DELETE_WINDOW', self.frame2_encode_cleanup)

    def frame2_encode_cleanup(self):
        self.frame2_encode_window = None

    def info(self):
        try:
            if self.decoded_image_path:
                decoded_image_size = os.stat(self.decoded_image_path)
                decoded_image = Image.open(self.decoded_image_path)
                decoded_image_width, decoded_image_height = decoded_image.size

                str_info = f"Decoded image:\nSize: {decoded_image_size.st_size / 1000000} MB\nWidth: {decoded_image_width}\nHeight: {decoded_image_height}"
                messagebox.showinfo("Info", str_info)
            else:
                messagebox.showinfo("Info", "No decoded image found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def enc_fun(self, text, img):
        data = text.get("1.0", 'end-1c')
        if len(data) == 0:
            messagebox.showerror("Error", "You haven't entered any message !")
        elif self.o_image_w * self.o_image_h < len(data) * 3:
            messagebox.showerror("Error", "Selected Image is too small !")
        else:
            encoded_image = self.encode(data, img)

            if encoded_image:
                save_path = tkinter.filedialog.asksaveasfilename(defaultextension=".png")
                if save_path:
                    encoded_image.save(save_path)
                    messagebox.showinfo("Success", "Image encoded and saved successfully.")
                    self.log("Image encoded and saved successfully")
                    self.frame2_encode_window.withdraw()
                    self.root.deiconify()
                else:
                    messagebox.showerror("Error", "Invalid save path.")

        self.frame2_encode_window.destroy()
        self.root.deiconify()

    def encode(self, data, image):

        if self.is_encoded(image):
            messagebox.showwarning("Warning", "The image is already encoded.")
            self.log("Warning, The image is already encoded")
            return None
        
        newimg = image.copy()
        self.width, self.height = image.size
        if self.is_last_pixel_used(newimg):
            messagebox.showwarning("Warning", "The last pixel of the image is already used for encoding.")
            self.log("Warning", "The last pixel of the image is already used for encoding.")
            return None

        self.encode_enc(newimg, data)
        return newimg
    

    def is_last_pixel_used(self, image):
        last_pixel = image.getpixel((self.width - 1, self.height - 1))

        if any(value % 2 == 1 for value in last_pixel):
            return True

        return False
    
    def modPix(self, pixel, data):
        datalist = self.genData(data)
        lendata = len(datalist)
        imdata = iter(pixel)
        for i in range(lendata):
            pix = [value for value in imdata.__next__()[:3] +
                   imdata.__next__()[:3] +
                   imdata.__next__()[:3]]            
            for j in range(0, 8):
                if (datalist[i][j] == '0' and pix[j] % 2 != 0):
                    pix[j] -= 1
                elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                    if (pix[j] != 0):
                        pix[j] -= 1
                    else:
                        pix[j] += 1               
            if (i == lendata - 1):
                if (pix[-1] % 2 == 0):
                    if (pix[-1] != 0):
                        pix[-1] -= 1
                    else:
                        pix[-1] += 1
            else:
                if (pix[-1] % 2 != 0):
                    pix[-1] -= 1
            pix = tuple(pix)
            yield pix[0:3]
            yield pix[3:6]
            yield pix[6:9]
    def encode_enc(self, newimg, data):
        w = newimg.size[0]
        (x, y) = (0, 0)
        for pixel in self.modPix(newimg.getdata(), data):

            newimg.putpixel((x, y), pixel)
            if (x == w - 1):
                x = 0
                y += 1
            else:
                x += 1

    def genData(self, data):
        
        newd = []
        for i in data:
            newd.append(format(ord(i), '08b'))
        return newd

    def is_encoded(self, image_path):
        try:
            image = Image.open(image_path)
            image_data = image.getdata()

            last_pixel = image_data[-1]
            for value in last_pixel:
                if value % 2 == 1:
                    return True
            return False
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            return False

stegno_obj = Stegno()
stegno_obj.main()
root = tk.Tk()  
root.mainloop()


