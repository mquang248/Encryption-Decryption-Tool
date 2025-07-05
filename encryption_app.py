import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
from PIL import Image, ImageTk
import io
import os

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Encryption/Decryption Tool")
        self.root.geometry("700x500")
        
        # Set theme and style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('TButton', padding=5)
        style.configure('TLabel', padding=5)
        style.configure('TFrame', padding=5)
        style.configure('TLabelframe', padding=10)
        style.configure('TLabelframe.Label', font=('Arial', 10, 'bold'))
        
        # Generate a random key for AES encryption
        self.key = get_random_bytes(32)  # 256-bit key
        
        # Create tabs
        self.tab_control = ttk.Notebook(root)
        self.tab_control.pack(expand=1, fill="both", padx=10, pady=5)
        
        # Text encryption tab
        self.text_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.text_tab, text='Text Encryption')
        
        # File encryption tab
        self.file_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.file_tab, text='File Encryption')
        
        self.setup_text_tab()
        self.setup_file_tab()
        
        # Add status bar
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)
    
    def setup_text_tab(self):
        # Input section
        input_frame = ttk.LabelFrame(self.text_tab, text="Input")
        input_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create text input with white cursor
        self.text_input = tk.Text(
            input_frame, 
            height=6, 
            width=50,
            insertbackground='white',  # White cursor
            bg='#2d2d2d',  # Dark background
            fg='white',    # White text
            selectbackground='#454545',  # Selection background
            selectforeground='white',    # Selection text color
            font=('Consolas', 10)
        )
        self.text_input.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        
        # Buttons frame
        btn_frame = ttk.Frame(input_frame)
        btn_frame.pack(pady=5)
        
        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_text).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_text).pack(side=tk.LEFT, padx=5)
        
        # Output section
        output_frame = ttk.LabelFrame(self.text_tab, text="Result")
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create a frame for the output and copy button
        result_frame = ttk.Frame(output_frame)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Output text area with white cursor
        self.text_output = tk.Text(
            result_frame, 
            height=6, 
            width=50,
            insertbackground='white',  # White cursor
            bg='#2d2d2d',  # Dark background
            fg='white',    # White text
            selectbackground='#454545',  # Selection background
            selectforeground='white',    # Selection text color
            font=('Consolas', 10)
        )
        self.text_output.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Copy button frame
        copy_frame = ttk.Frame(result_frame)
        copy_frame.pack(side=tk.LEFT, fill=tk.Y)
        
        # Copy button with icon
        copy_btn = ttk.Button(
            copy_frame, 
            text="Copy", 
            command=self.copy_result,
            width=8
        )
        copy_btn.pack(pady=2)
    
    def setup_file_tab(self):
        # File selection frame
        file_frame = ttk.LabelFrame(self.file_tab, text="File Selection")
        file_frame.pack(fill=tk.X, padx=10, pady=5)
        
        select_frame = ttk.Frame(file_frame)
        select_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.file_path = tk.StringVar()
        path_entry = ttk.Entry(
            select_frame, 
            textvariable=self.file_path,
            style='Custom.TEntry'
        )
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(select_frame, text="Browse", command=self.browse_file)
        browse_btn.pack(side=tk.LEFT)
        
        # File info frame
        self.file_info_frame = ttk.LabelFrame(self.file_tab, text="File Information")
        self.file_info_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.file_info_label = ttk.Label(self.file_info_frame, text="No file selected")
        self.file_info_label.pack(padx=10, pady=10)
        
        # Actions frame
        actions_frame = ttk.LabelFrame(self.file_tab, text="Actions")
        actions_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        btn_frame = ttk.Frame(actions_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
    
    def copy_result(self):
        try:
            result = self.text_output.get("1.0", tk.END).strip()
            if result:
                self.root.clipboard_clear()
                self.root.clipboard_append(result)
                self.status_var.set("Result copied to clipboard!")
                self.root.after(2000, lambda: self.status_var.set(""))
            else:
                self.status_var.set("No result to copy!")
        except Exception as e:
            self.status_var.set("Failed to copy: " + str(e))
    
    def encrypt_text(self):
        try:
            text = self.text_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showerror("Error", "Please enter text to encrypt")
                return
                
            cipher = AES.new(self.key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
            iv = base64.b64encode(cipher.iv).decode('utf-8')
            ct = base64.b64encode(ct_bytes).decode('utf-8')
            result = f'{iv}:{ct}'
            
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", result)
            self.status_var.set("Text encrypted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            self.status_var.set("Encryption failed!")
    
    def decrypt_text(self):
        try:
            text = self.text_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showerror("Error", "Please enter text to decrypt")
                return
            
            try:
                iv, ct = text.split(':')
            except ValueError:
                messagebox.showerror("Error", "Invalid encrypted text format")
                return
                
            try:
                iv = base64.b64decode(iv)
                ct = base64.b64decode(ct)
            except Exception:
                messagebox.showerror("Error", "Invalid encrypted text")
                return
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)
            
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert("1.0", pt.decode())
            self.status_var.set("Text decrypted successfully!")
        except ValueError as e:
            if "padding" in str(e).lower():
                messagebox.showerror("Error", "Decryption failed: Invalid padding")
            else:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status_var.set("Decryption failed!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
            self.status_var.set("Decryption failed!")
    
    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)
            self.update_file_info(filename)
            self.status_var.set(f"Selected: {os.path.basename(filename)}")
    
    def update_file_info(self, filepath):
        if not filepath or not os.path.exists(filepath):
            self.file_info_label.config(text="No file selected")
            return
            
        file_size = os.path.getsize(filepath)
        file_name = os.path.basename(filepath)
        
        if file_size < 1024:
            size_str = f"{file_size} bytes"
        elif file_size < 1024*1024:
            size_str = f"{file_size/1024:.1f} KB"
        else:
            size_str = f"{file_size/(1024*1024):.1f} MB"
            
        info_text = f"File: {file_name}\nSize: {size_str}"
        self.file_info_label.config(text=info_text)
    
    def is_encrypted_file(self, filepath):
        try:
            if not os.path.exists(filepath):
                return False
                
            if os.path.getsize(filepath) < 16 + AES.block_size:
                return False
                
            with open(filepath, 'rb') as f:
                iv = f.read(16)
                if len(iv) != 16:
                    return False
                    
            return True
        except:
            return False
    
    def encrypt_file(self):
        try:
            input_file = self.file_path.get()
            if not input_file:
                messagebox.showerror("Error", "Please select a file")
                return
                
            if not os.path.exists(input_file):
                messagebox.showerror("Error", "File does not exist")
                return
                
            if self.is_encrypted_file(input_file):
                if not messagebox.askyesno("Warning", "This file appears to be already encrypted. Do you want to encrypt it again?"):
                    return
                
            output_file = filedialog.asksaveasfilename(
                defaultextension=".encrypted",
                filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
            )
            if not output_file:
                return
                
            with open(input_file, 'rb') as file:
                data = file.read()
            
            cipher = AES.new(self.key, AES.MODE_CBC)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            
            with open(output_file, 'wb') as file:
                file.write(cipher.iv)
                file.write(ct_bytes)
                
            self.status_var.set("File encrypted successfully!")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
            if self.file_path.get() == output_file:
                self.update_file_info(output_file)
                
        except Exception as e:
            self.status_var.set("File encryption failed!")
            messagebox.showerror("Error", f"File encryption failed: {str(e)}")
    
    def decrypt_file(self):
        try:
            input_file = self.file_path.get()
            if not input_file:
                messagebox.showerror("Error", "Please select a file")
                return
                
            if not os.path.exists(input_file):
                messagebox.showerror("Error", "File does not exist")
                return
                
            if not self.is_encrypted_file(input_file):
                messagebox.showerror("Error", "This file does not appear to be encrypted")
                return
                
            output_file = filedialog.asksaveasfilename(
                defaultextension=".decrypted",
                filetypes=[("Decrypted files", "*.decrypted"), ("All files", "*.*")]
            )
            if not output_file:
                return
                
            with open(input_file, 'rb') as file:
                iv = file.read(16)
                ct_bytes = file.read()
            
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            
            try:
                pt = unpad(cipher.decrypt(ct_bytes), AES.block_size)
            except ValueError:
                messagebox.showerror("Error", "Decryption failed: Invalid file format")
                return
            
            with open(output_file, 'wb') as file:
                file.write(pt)
                
            self.status_var.set("File decrypted successfully!")
            messagebox.showinfo("Success", "File decrypted successfully!")
            
            if self.file_path.get() == output_file:
                self.update_file_info(output_file)
                
        except Exception as e:
            self.status_var.set("File decryption failed!")
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop() 