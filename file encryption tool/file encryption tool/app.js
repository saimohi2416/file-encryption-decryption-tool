
SecureVault
Military-Grade Encryption
Encrypt & Decrypt
Any File, Instantly
Secure your files with AES-256-GCM encryption — the same standard used by banks and governments. Everything runs 100% in your browser. No uploads, no servers, no data leaks.

Encrypt File
Decrypt File
Step-by-Step Process
01
Select File
Choose the file to process
02
Enter Password
Set your encryption key
03
Key Derivation
PBKDF2 with SHA-256
04
AES-256-GCM Encrypt
Encrypt file data
05
Download Result
Save the processed file
Step 1 — Select File
File Explorer
Desktop
Documents
Downloads
report.pdf
data.zip
secret.doc
Browse Files
Open folder window or drag & drop
Open Folder
Step 2 — Encryption Password
Enter a strong password...

Enter password
At least 8 characters
Uppercase letter
Number
Special symbol
Confirm Password
Re-enter password to confirm...
Encryption Details
Algorithm
AES-256-GCM
Key Derivation
PBKDF2
Hash Function
SHA-256
Iterations
310,000
Salt Length
16 bytes
IV Length
12 bytes

Encrypt File
All processing happens locally in your browser. Files never leave your device.

How AES-256-GCM Encryption Works
1
Salt Generation
A cryptographically random 16-byte salt is generated to ensure each encryption produces a unique output, even with the same password.

2
Key Derivation (PBKDF2)
Your password is run through PBKDF2 with SHA-256 hash function and 310,000 iterations to produce a strong 256-bit AES key.

3
IV Generation
A unique 12-byte Initialization Vector (IV) is randomly generated for GCM mode, ensuring cipher randomness and preventing replay attacks.

4
AES-256-GCM Encryption
File data is encrypted using AES in Galois/Counter Mode (GCM), providing both confidentiality and authentication with a 128-bit auth tag.

5
Output Packaging
The salt, IV, and ciphertext are concatenated into a single .enc file. This self-contained file holds everything needed for decryption (except your password).

6
Zero-Knowledge Security
Your password and file data never leave your browser. All cryptographic operations use the browser's built-in Web Crypto API with no external libraries.

SecureVault — AES-256-GCM File Encryption Tool  •  Built with Web Crypto API  •  Zero data transmission




This PC
›
Desktop
Search...


Quick Access
Desktop
Documents
Downloads
Pictures
This PC
Local Disk (C:)
Drop a file here to select it

No item selected
Cancel
Open File
Pressing key...Getting DOM...Stopping...

Stop Agent
