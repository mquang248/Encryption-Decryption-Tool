# Encryption/Decryption Tool

A secure and user-friendly desktop application for encrypting and decrypting text and files using AES-256 encryption.

## Features

- Text encryption and decryption
- File encryption and decryption (supports all file types)
- Modern and intuitive graphical interface
- AES-256 encryption in CBC mode
- Secure random key generation
- Cross-platform support (Windows and Linux)

## Function

- Text Encryption Tab: Input text, click Encrypt/Decrypt, and easily copy results
- File Encryption Tab: Select files, encrypt/decrypt with progress feedback

## Installation

### Windows

1. Install Python 3.x:
   - Download Python from [python.org](https://www.python.org/downloads/)
   - During installation, make sure to check "Add Python to PATH"
   - Verify installation by opening Command Prompt and typing:
     ```
     python --version
     ```

2. Install required packages:
   ```cmd
   # Open Command Prompt as normal user
   pip install pycryptodome pillow
   ```

3. Download and run:
   ```cmd
   # Clone repository (if you have git)
   git clone https://github.com/yourusername/encryption-tool
   cd encryption-tool

   # Or download and extract ZIP file
   
   # Run the application
   python encryption_app.py
   ```

### Linux

1. Install Python and required system packages:

   **Ubuntu/Debian:**
   ```bash
   sudo apt update
   sudo apt install python3 python3-pip python3-tk
   ```

   **Fedora:**
   ```bash
   sudo dnf install python3 python3-pip python3-tkinter
   ```

   **Arch Linux:**
   ```bash
   sudo pacman -S python python-pip tk
   ```

2. Create and activate virtual environment (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install required Python packages:
   ```bash
   pip install pycryptodome pillow
   ```

4. Run the application:
   ```bash
   python encryption_app.py
   ```

## Usage Guide

### Text Encryption

1. Select the "Text Encryption" tab
2. Enter your text in the input field
3. Click "Encrypt" to encrypt the text
4. The encrypted text will appear in the result field
5. Use the "Copy" button to copy the encrypted text
6. To decrypt: paste encrypted text in input field and click "Decrypt"

### File Encryption

1. Select the "File Encryption" tab
2. Click "Browse" to select a file
3. Click "Encrypt File" to encrypt
4. Choose location to save encrypted file (.encrypted extension)
5. To decrypt: select encrypted file and click "Decrypt File"
6. Choose location to save decrypted file

## Security Notes

- The encryption key is randomly generated each time you start the application
- Encrypted data can only be decrypted in the same session
- Close and restart the application to generate a new encryption key
- For long-term storage, consider implementing key management
- Always keep backups of important files before encryption

## Technical Details

- Encryption Algorithm: AES-256-CBC
- Key Size: 256 bits
- Initialization Vector (IV): Random, unique per encryption
- Padding: PKCS7
- File Format: IV (16 bytes) + Encrypted Data
- Text Format: Base64(IV):Base64(Encrypted Data)

## Troubleshooting

### Common Issues

1. "No module named 'Crypto'":
   ```bash
   pip install pycryptodome
   ```

2. "No module named 'tkinter'":
   - Windows: Reinstall Python with tkinter
   - Linux: Install python3-tk package

3. "Permission denied":
   - Windows: Run Command Prompt as administrator
   - Linux: Use sudo for system packages

### Error Messages

- "Invalid encrypted text format": The input text is not in the correct encryption format
- "Invalid padding": The text/file was not encrypted by this tool or is corrupted
- "File does not appear to be encrypted": Trying to decrypt a non-encrypted file

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 
