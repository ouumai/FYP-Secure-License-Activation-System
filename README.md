### 🛠️ Technical Specifications

The system is built using **Python 3.10+**  and utilizes the following libraries:


**`pycryptodome`**: Implements **AES encryption** (ECB mode) to secure license keys against tampering.



**`hashlib`**: Provides **SHA-256 hashing** to store user passwords as irreversible strings for secure authentication.



**`wmi` / `uuid**`: Retrieves unique **Hardware IDs** (Motherboard serial/MAC address) to bind the license to a specific device.



**`customTkinter`**: Creates a modern **Graphical User Interface (GUI)** for both the License Generator and Validator.



**`sqlite3`**: Manages a local **`users.db`** database for admin-level user control.



**`PyInstaller`**: Compiles scripts into standalone **.exe** files, removing Python dependency for end-users.



### ⚙️ System Logic & Functions

1. 
**Hardware Fingerprinting**: Captures device-specific data to generate a unique **Request Code**.


2. 
**Encryption/Decryption**: The developer encrypts the Request Code using a secret key; the software decrypts it locally to verify the match .


3. 
**Local Validation**: Upon success, it creates a `license_ok.txt` file to grant offline access without needing external servers.
