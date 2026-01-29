import customtkinter as ctk
from tkinter import messagebox, Menu
import hashlib
from Crypto.Cipher import AES
import base64

# ===== Config =====
SECRET_KEY = "MySecretKey"   # keep it private (don't share it with user)
DEV_PASSWORD = "Admin123"    # password to open the generator

# ===== Functions =====
def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text

def generate_license_key(request_code):
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(request_code)
    encrypted = cipher.encrypt(padded.encode())
    return base64.b64encode(encrypted).decode()

def handle_generate():
    request_code = entry_request.get()
    dev_password = entry_password.get()

    # Check Developer Password
    if dev_password != DEV_PASSWORD:
        messagebox.showerror("Error", "Invalid Developer Password!", parent=window)
        return

    if not request_code:
        messagebox.showerror("Error", "Please Fill in the Request Code.", parent=window)
        return

    license_key = generate_license_key(request_code)
    text_result.delete("1.0", "end")
    text_result.insert("end", license_key)

def handle_paste():
    try:
        pasted_text = window.clipboard_get()
        entry_request.delete(0, "end")
        entry_request.insert(0, pasted_text)
    except:
        messagebox.showerror("Error", "Clipboard is empty!", parent=window)

def handle_copy():
    license_key = text_result.get("1.0", "end").strip()
    if license_key:
        window.clipboard_clear()
        window.clipboard_append(license_key)
        window.update()
        messagebox.showinfo("Copied", "License Key copied to clipboard!", parent=window)
    else:
        messagebox.showerror("Error", "No License Key to copy!", parent=window)

def show_about():
    messagebox.showinfo("About",
        "License Key Generator (Developer Only)\n"
        "Version: 1.2\n"
        "Developed by:\n"
        "Mohamad Faidhi Bin Ahmad Fauzil (21DDT23F1141)\n"
        "Nur Azurin Binti Mohd Radzi (21DDT23F1097)\n"
        "Nur Umairah Binti Mohd Sabri (21DDT23F1099)\n", parent=window)

# ===== GUI =====
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("green")

window = ctk.CTk()
window.title("License Key Generator (Developer Only)")
# MODIFIED: Increased height from 450 to 520 to make button visible
window.geometry("520x520")
window.resizable(False, False) # This window should not be resizable

# ===== Menu Bar =====
menubar = Menu(window)
menubar.add_command(label="About", command=show_about)
menubar.add_command(label="Exit", command=window.destroy)
window.configure(menu=menubar)

# Title
title = ctk.CTkLabel(window, text="License Key Generator", font=("Segoe UI", 22, "bold"))
title.pack(pady=20)

# Request Code Input
label_request = ctk.CTkLabel(window, text="Enter Request Code from User:", font=("Segoe UI", 14))
label_request.pack(pady=5)

frame_request = ctk.CTkFrame(window, fg_color="transparent")
frame_request.pack(pady=5)

entry_request = ctk.CTkEntry(frame_request, width=280, placeholder_text="Paste User Request Code Here")
entry_request.grid(row=0, column=0, padx=5)

btn_paste = ctk.CTkButton(frame_request, text="Paste", command=handle_paste, width=60, height=30)
btn_paste.grid(row=0, column=1, padx=5)

# Developer Password Input
label_password = ctk.CTkLabel(window, text="Enter Developer Password:", font=("Segoe UI", 14))
label_password.pack(pady=10)

entry_password = ctk.CTkEntry(window, width=350, show="*", placeholder_text="Enter Developer Password")
entry_password.pack(pady=5)

# Generate Button
btn_generate = ctk.CTkButton(window, text="Generate License Key", command=handle_generate,
                             width=220, height=40, corner_radius=10)
btn_generate.pack(pady=20)

# Result
label_result = ctk.CTkLabel(window, text="Generated License Key:", font=("Segoe UI", 14))
label_result.pack(pady=5)

text_result = ctk.CTkTextbox(window, width=350, height=100)
text_result.pack(pady=5)

#Copy Button under textbox
btn_copy = ctk.CTkButton(window, text="Copy", command=handle_copy, width=120, height=35, corner_radius=8)
btn_copy.pack(pady=10)

window.mainloop()
