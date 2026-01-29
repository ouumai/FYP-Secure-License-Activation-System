import os
import sys
import sqlite3
import hashlib
import customtkinter as ctk
from tkinter import messagebox, Menu
from tkinter import ttk
import platform
import uuid

#optional imports for activation HWID + crypto
#REMOVED: wmi (can cause hanging on startup)

try:
    from Crypto.Cipher import AES
    import base64
except Exception:
    AES = None
    base64 = None

# ----------------- Configuration -----------------
# Detect correct folder whether running as .py or PyInstaller .exe
if getattr(sys, 'frozen', False):
    # If running as a bundled EXE (PyInstaller)
    APP_PATH = os.path.dirname(sys.executable)
else:
    # If running from a normal .py file
    APP_PATH = os.path.dirname(os.path.abspath(__file__))

DB_FILE = os.path.join(APP_PATH, "users.db")
LICENSE_FILE = os.path.join(APP_PATH, "license_ok.txt")
SECRET_KEY_FOR_LICENSE = "MySecretKey"  # developer must use same key to create license


# ----------------- Database helpers -----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""
              CREATE TABLE IF NOT EXISTS users
              (
                  id
                  INTEGER
                  PRIMARY
                  KEY
                  AUTOINCREMENT,
                  username
                  TEXT
                  UNIQUE,
                  password
                  TEXT,
                  role
                  TEXT
              )
              """)
    # create default admin if none
    c.execute("SELECT * FROM users WHERE role='admin'")
    if not c.fetchone():
        default_pass = hashlib.sha256("Admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  ("User@admin", default_pass, "admin"))
    conn.commit()
    conn.close()


def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()


def validate_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT role, password FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if row and row[1] == hash_pw(password):
        return row[0]
    return None


def add_user(username, password):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                  (username, hash_pw(password), "user"))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False


def change_credentials(old_username, new_username, new_password):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("UPDATE users SET username=?, password=? WHERE username=?",
                  (new_username, hash_pw(new_password), old_username))
        conn.commit()
        success = c.rowcount > 0
        conn.close()
        return success
    except sqlite3.IntegrityError:
        return False


def get_all_users():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT id, username, role FROM users ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return rows


def delete_user_by_id(user_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    affected = c.rowcount
    conn.close()
    return affected > 0


# ----------------- Activation helpers -----------------
def get_request_code():
    """
    Get a unique machine ID.
    FIXED: Removed wmi to prevent hanging on startup.
    """
    # Use reliable fallback (cross-platform): node + mac hashed (short)
    node = platform.node() or ""
    mac = hex(uuid.getnode())[2:]
    fallback = hashlib.sha256((node + mac).encode()).hexdigest()[:24]
    return fallback


def pad(text):
    while len(text) % 16 != 0:
        text += ' '
    return text


def decrypt_license(encrypted_key, secret_key):
    """Decrypt base64 AES-ECB license key and return plaintext (or None)."""
    if AES is None or base64 is None:
        return None
    try:
        key = hashlib.sha256(secret_key.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_key)).decode(errors="ignore").strip()
        return decrypted
    except Exception:
        return None


# --- NEW FUNCTION (SECURITY FIX) ---
def check_license():
    """
    Check if the license file exists and is valid for this hardware.
    Returns True if valid, False otherwise.
    """
    if not os.path.exists(LICENSE_FILE):
        return False  # No license file

    if AES is None or base64 is None:
        print("Crypto libraries not found. Cannot verify license.")
        return False

    try:
        with open(LICENSE_FILE, "r") as f:
            encrypted_key_from_file = f.read().strip()

        if not encrypted_key_from_file:
            return False  # License file is empty

        current_hardware_id = get_request_code()
        decrypted_id = decrypt_license(encrypted_key_from_file, SECRET_KEY_FOR_LICENSE)

        # The core check:
        return decrypted_id == current_hardware_id

    except Exception as e:
        print(f"Error checking license: {e}")
        return False


# ----------------- Activation window -----------------
def run_activation_window():
    """
    Show activation window.
    """
    act = ctk.CTk()
    act.title("Software License Activation")
    act.geometry("520x380")
    act.resizable(False, False)  # This window should not be resizable

    # menu
    menubar = Menu(act)

    def show_about():
        messagebox.showinfo("About",
                            "Secure License Activation System\n"
                            "Version 1.0 (FYP Project 2025)\n\n"
                            "Developed by:\n"
                            "• Mohamad Faidhi Bin Ahmad Fauzil (21DDT23F1141)\n"
                            "• Nur Azurin Binti Mohd Radzi (21DDT23F1097)\n"
                            "• Nur Umairah Binti Mohd Sabri (21DDT23F1099)\n\n"
                            "Supervised by: TS. Anirah Binti Ahmad\n"
                            "Institution: Politeknik Balik Pulau", parent=act)

    menubar.add_command(label="About", command=show_about)
    menubar.add_command(label="Exit", command=act.destroy)
    act.configure(menu=menubar)

    ctk.CTkLabel(act, text="Software License Activation System", font=("Segoe UI", 20, "bold")).pack(pady=18)
    ctk.CTkLabel(act, text="Request Code (send to developer):", font=("Segoe UI", 13)).pack(pady=(6, 4))

    request_code = get_request_code()

    frame_request = ctk.CTkFrame(act, fg_color="transparent")
    frame_request.pack(pady=6)

    entry_request = ctk.CTkEntry(frame_request, width=360, justify="center")
    entry_request.insert(0, request_code)
    entry_request.configure(state="readonly")
    entry_request.grid(row=0, column=0, padx=(0, 6))

    def copy_request_code():
        act.clipboard_clear()
        act.clipboard_append(request_code)
        act.update()
        messagebox.showinfo("Copied", "Request Code copied to clipboard!", parent=act)

    btn_copy = ctk.CTkButton(frame_request, text="Copy", command=copy_request_code, width=100)
    btn_copy.grid(row=0, column=1)

    ctk.CTkLabel(act, text="Enter License Key:", font=("Segoe UI", 13)).pack(pady=(14, 6))

    frame_license = ctk.CTkFrame(act, fg_color="transparent")
    frame_license.pack(pady=4)

    entry_license = ctk.CTkEntry(frame_license, width=360, placeholder_text="Paste Your License Key Here")
    entry_license.grid(row=0, column=0, padx=(0, 6))

    def paste_from_clipboard():
        try:
            txt = act.clipboard_get()
            entry_license.delete(0, "end")
            entry_license.insert(0, txt)
        except Exception:
            messagebox.showerror("Error", "Clipboard empty", parent=act)

    btn_paste = ctk.CTkButton(frame_license, text="Paste", command=paste_from_clipboard, width=100)
    btn_paste.grid(row=0, column=1)

    def validate_key_action():
        entered = entry_license.get().strip()
        if not entered:
            messagebox.showwarning("Warning", "Please enter a license key", parent=act)
            return
        if AES is None or base64 is None:
            messagebox.showerror("Error", "Crypto library missing. Cannot validate license here.", parent=act)
            return

        decrypted = decrypt_license(entered, SECRET_KEY_FOR_LICENSE)
        expected_id = request_code

        if decrypted and decrypted == expected_id:
            try:
                # --- MODIFIED (SECURITY FIX) ---
                # Write the *encrypted key* to the file, not "Activated"
                with open(LICENSE_FILE, "w") as f:
                    f.write(entered)
                # --- END MODIFIED ---
                messagebox.showinfo("Success", "License valid. Software activated!", parent=act)
            except Exception as e:
                messagebox.showerror("Error", f"Could not write license file: {e}", parent=act)
            act.destroy()
        else:
            messagebox.showerror("Invalid", "License key not valid for this device.", parent=act)

    btn_validate = ctk.CTkButton(act, text="Validate License", command=validate_key_action, width=220, height=40)
    btn_validate.pack(pady=22)

    ctk.CTkLabel(act, text="If you don't have a license key, send the Request Code to the developer.",
                 font=("Segoe UI", 10)).pack(pady=(6, 8))

    act.mainloop()
    # No return value needed, main startup logic will re-check


# ----------------- Main App class (login + admin menu + DB features) -----------------
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Secure License Activation System")
        # MODIFIED: Use minsize to allow resizing
        self.minsize(500, 400)
        self.current_user = None
        self.admin_win = None

        # MODIFIED: Configure resizing for the main window
        # Give all weight to row 0, col 0
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        init_db()
        self.show_login()

    def clear(self):
        # Clear all widgets from the main window
        for w in self.winfo_children():
            # Do not destroy the menu
            if not isinstance(w, (Menu, ctk.CTkToplevel)):
                # MODIFIED: Use grid_forget() instead of pack_forget()
                w.grid_forget()
        # Reset the menu for the main window to empty
        self.config(menu=Menu(self))

    def show_login(self):
        self.clear()
        self.title("Secure License Activation System")  # Reset title

        # MODIFIED: Use grid and center everything
        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.grid(row=0, column=0, sticky="nsew", pady=20, padx=20)

        # Configure main_frame's grid to center its contents
        main_frame.grid_rowconfigure(0, weight=1)  # Space above
        main_frame.grid_rowconfigure(1, weight=0)  # Title
        main_frame.grid_rowconfigure(2, weight=0)  # Subtitle
        main_frame.grid_rowconfigure(3, weight=0)  # Login Frame
        main_frame.grid_rowconfigure(4, weight=1)  # Space below
        main_frame.grid_rowconfigure(5, weight=0)  # Footer
        main_frame.grid_columnconfigure(0, weight=1)  # Center horizontally

        ctk.CTkLabel(main_frame, text="Welcome To Secure License Activation System",
                     font=("Segoe UI", 20, "bold")).grid(
            row=1, column=0, pady=(30, 5), padx=20)
        ctk.CTkLabel(main_frame, text="Please login to continue", font=("Segoe UI", 14)).grid(
            row=2, column=0, pady=(0, 20), padx=20)

        login_frame = ctk.CTkFrame(main_frame, corner_radius=12, fg_color="#f2f2f2", width=320, height=220)
        login_frame.grid(row=3, column=0, pady=10)
        login_frame.pack_propagate(False)

        ctk.CTkLabel(login_frame, text="Username", font=("Segoe UI", 13, "bold")).pack(pady=(15, 5))
        username = ctk.CTkEntry(login_frame, width=240, justify="center", placeholder_text="Enter Username")
        username.pack(pady=(0, 10))

        ctk.CTkLabel(login_frame, text="Password", font=("Segoe UI", 13, "bold")).pack(pady=(5, 5))
        password = ctk.CTkEntry(login_frame, width=240, justify="center", placeholder_text="Enter Password", show="*")
        password.pack(pady=(0, 10))

        button_frame = ctk.CTkFrame(login_frame, fg_color="transparent")
        button_frame.pack(pady=5)

        def do_login():
            user = username.get().strip()
            pw = password.get().strip()
            role = validate_user(user, pw)
            if role == "admin":
                self.current_user = user
                self.open_admin_window()
            elif role == "user":
                self.current_user = user
                self.show_user_dashboard()
            else:
                messagebox.showerror("Login Failed", "Invalid Username or Password.", parent=self)

        def clear_fields():
            username.delete(0, "end")
            password.delete(0, "end")

        ctk.CTkButton(button_frame, text="Login", width=100, height=30, corner_radius=8, command=do_login).pack(
            side="left", padx=8)
        ctk.CTkButton(button_frame, text="Clear", width=80, height=30, corner_radius=8, fg_color="#808080",
                      hover_color="#666666", command=clear_fields).pack(side="left", padx=8)

        ctk.CTkLabel(main_frame, text="© 2025 Secure Activation System", font=("Segoe UI", 10)).grid(
            row=5, column=0, pady=10)

    # --- START: NEW AND UPDATED METHODS ---

    def perform_admin_logout_and_reset(self):
        """
        Safely destroys the admin window, resets the user,
        and shows the main login screen.
        """
        try:
            if self.admin_win:
                self.admin_win.destroy()
                self.admin_win = None
        except Exception as e:
            print(f"Error destroying admin window: {e}")

        self.current_user = None
        self.deiconify()
        self.show_login()

    def perform_user_logout_and_reset(self):
        """
        Safely resets the user and shows the main login screen.
        (For non-admin users)
        """
        self.current_user = None
        self.show_login()

    # Admin window with menubar
    def open_admin_window(self):
        self.withdraw()
        admin_win = ctk.CTkToplevel()
        self.admin_win = admin_win
        admin_win.title("Admin Dashboard")
        admin_win.minsize(700, 450)

        # Handle closing the admin window (e.g., with the 'X' button)
        admin_win.protocol("WM_DELETE_WINDOW", self.perform_admin_logout_and_reset)

        menubar = Menu(admin_win)

        # --- User Management Menu ---
        user_menu = Menu(menubar, tearoff=0)
        user_menu.add_command(label="Add User", command=self.open_add_user)
        user_menu.add_command(label="View Registered Users", command=self.open_view_users)
        menubar.add_cascade(label="User Management", menu=user_menu)

        # --- Admin Account Menu ---
        admin_menu = Menu(menubar, tearoff=0)
        admin_menu.add_command(label="Change Password", command=self.open_change_password)
        menubar.add_cascade(label="Admin Account", menu=admin_menu)

        # --- Help Menu (About Team Info) ---
        help_menu = Menu(menubar, tearoff=0)

        def show_about():
            messagebox.showinfo(
                "About",
                "Secure License Activation System\n"
                "Version 1.0 (FYP Project 2025)\n\n"
                "Developed by:\n"
                "• Mohamad Faidhi Bin Ahmad Fauzil (21DDT23F1141)\n"
                "• Nur Azurin Binti Mohd Radzi (21DDT23F1097)\n"
                "• Nur Umairah Binti Mohd Sabri (21DDT23F1099)\n\n"
                "Supervised by: TS. Anirah Binti Ahmad\n"
                "Institution: Politeknik Balik Pulau",
                parent=admin_win
            )

        help_menu.add_command(label="About", command=show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        # --- Logout Button ---
        menubar.add_command(label="Logout", command=self.perform_admin_logout_and_reset)

        # --- Apply Menubar ---
        admin_win.config(menu=menubar)

        # MODIFIED: Configure grid to center content
        admin_win.grid_rowconfigure(0, weight=1)
        admin_win.grid_columnconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(admin_win, fg_color="transparent")
        main_frame.grid(row=0, column=0)

        ctk.CTkLabel(main_frame, text=f"Welcome, {self.current_user}", font=("Segoe UI", 22, "bold")).pack(pady=30,
                                                                                                           padx=20)
        ctk.CTkLabel(main_frame, text="Use the menu bar above to manage users and settings.",
                     font=("Segoe UI", 14)).pack(pady=10, padx=20)

    def open_add_user(self):
        win = ctk.CTkToplevel(self.admin_win or self)
        win.title("Add User")
        win.geometry("420x360")
        win.resizable(False, False)  # This window should not be resizable
        win.transient(self.admin_win or self)  # Keep it on top
        win.grab_set()  # Modal behavior

        ctk.CTkLabel(win, text="Add New User", font=("Segoe UI", 16, "bold")).pack(pady=(15, 10))
        ctk.CTkLabel(win, text="Username", anchor="w").pack(padx=20, pady=(6, 2), fill="x")
        entry_user = ctk.CTkEntry(win, width=300);
        entry_user.pack(padx=20)
        ctk.CTkLabel(win, text="Password", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_pass = ctk.CTkEntry(win, width=300, show="*");
        entry_pass.pack(padx=20)
        ctk.CTkLabel(win, text="Confirm Password", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_pass2 = ctk.CTkEntry(win, width=300, show="*");
        entry_pass2.pack(padx=20)

        def on_add():
            u = entry_user.get().strip();
            p = entry_pass.get().strip();
            p2 = entry_pass2.get().strip()
            if not u or not p:
                messagebox.showwarning("Warning", "Please fill all fields", parent=win);
                return
            if p != p2:
                messagebox.showwarning("Warning", "Passwords do not match", parent=win);
                return
            ok = add_user(u, p)
            if ok:
                messagebox.showinfo("Success", f"User '{u}' added.", parent=win);
                entry_user.delete(0, "end");
                entry_pass.delete(0, "end");
                entry_pass2.delete(0, "end")
            else:
                messagebox.showerror("Error", "Username already exists.", parent=win)

        ctk.CTkButton(win, text="Add User", command=on_add, width=140).pack(pady=18)

    def open_view_users(self):
        win = ctk.CTkToplevel(self.admin_win or self)
        win.title("View Registered Users")
        win.minsize(600, 400)
        win.transient(self.admin_win or self)  # Keep it on top
        win.grab_set()  # Modal behavior

        # --- MODIFIED: Configure grid resizing ---
        # Make the window's main column expand
        win.grid_columnconfigure(0, weight=1)
        # Make the row containing the tree (row 1) expand
        win.grid_rowconfigure(1, weight=1)
        # --- END MODIFIED ---

        ctk.CTkLabel(win, text="Registered Users", font=("Segoe UI", 16, "bold")).grid(row=0, column=0, pady=(10, 8))

        frame = ctk.CTkFrame(win)
        # MODIFIED: Use grid and sticky="nsew"
        frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=8)  # nsew = north, south, east, west

        # --- MODIFIED: Configure grid resizing for frame content ---
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        # --- END MODIFIED ---

        columns = ("id", "username", "role")
        tree = ttk.Treeview(frame, columns=columns, show="headings", height=14)
        tree.heading("id", text="ID");
        tree.heading("username", text="Username");
        tree.heading("role", text="Role")
        tree.column("id", width=60, anchor="center");
        tree.column("username", width=380, anchor="w");
        tree.column("role", width=120, anchor="center")
        # MODIFIED: Use grid and sticky="nsew"
        tree.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=6)

        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview);
        tree.configure(yscrollcommand=vsb.set);
        # MODIFIED: Use grid and sticky="ns"
        vsb.grid(row=0, column=1, sticky="ns", pady=6)

        def load_data():
            for i in tree.get_children(): tree.delete(i)
            rows = get_all_users()
            for r in rows: tree.insert("", "end", values=r)

        def on_delete():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Warning", "Select a user to delete.", parent=win);
                return
            item = tree.item(sel[0]);
            user_id, username, role = item["values"]
            if role == "admin":
                messagebox.showerror("Error", "Cannot delete admin user.", parent=win);
                return
            confirm = messagebox.askyesno("Confirm", f"Delete user '{username}'?", parent=win)
            if not confirm: return
            ok = delete_user_by_id(user_id)
            if ok:
                messagebox.showinfo("Deleted", f"User '{username}' removed.", parent=win);
                load_data()
            else:
                messagebox.showerror("Error", "Failed to delete user.", parent=win)

        btn_frame = ctk.CTkFrame(win, fg_color="transparent")
        # MODIFIED: Use grid
        btn_frame.grid(row=2, column=0, pady=(6, 12))

        ctk.CTkButton(btn_frame, text="Refresh", command=load_data, width=120).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Delete Selected", command=on_delete, width=140, fg_color="#ff5c5c").pack(
            side="left", padx=6)

        load_data()

    def open_change_password(self):
        win = ctk.CTkToplevel(self.admin_win or self)
        win.title("Change Admin Credentials")
        win.geometry("420x380")
        win.resizable(False, False)  # This window should not be resizable
        win.transient(self.admin_win or self)  # Keep it on top
        win.grab_set()  # Modal behavior

        ctk.CTkLabel(win, text="Change Admin Username / Password", font=("Segoe UI", 15, "bold")).pack(pady=(12, 8))
        ctk.CTkLabel(win, text="Current Password", anchor="w").pack(padx=20, pady=(8, 2), fill="x")
        entry_old = ctk.CTkEntry(win, width=300, show="*");
        entry_old.pack(padx=20)
        ctk.CTkLabel(win, text="New Username (leave to keep same)", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_new_user = ctk.CTkEntry(win, width=300);
        entry_new_user.insert(0, self.current_user);
        entry_new_user.pack(padx=20)
        ctk.CTkLabel(win, text="New Password", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_new_pw = ctk.CTkEntry(win, width=300, show="*");
        entry_new_pw.pack(padx=20)
        ctk.CTkLabel(win, text="Confirm New Password", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_new_pw2 = ctk.CTkEntry(win, width=300, show="*");
        entry_new_pw2.pack(padx=20)

        def do_change():
            old_pw = entry_old.get().strip();
            new_user = entry_new_user.get().strip() or self.current_user
            new_pw = entry_new_pw.get().strip();
            new_pw2 = entry_new_pw2.get().strip()

            if not old_pw or not new_pw:
                messagebox.showwarning("Warning", "Please fill current password and new password.", parent=win);
                return
            if new_pw != new_pw2:
                messagebox.showwarning("Warning", "New passwords do not match.", parent=win);
                return

            role = validate_user(self.current_user, old_pw)
            if role != "admin":
                messagebox.showerror("Error", "Current password is incorrect.", parent=win);
                return

            ok = change_credentials(self.current_user, new_user, new_pw)

            if ok:
                messagebox.showinfo("Success", "Credentials updated. You must login again.", parent=win)
                win.destroy()  # Destroy this popup
                self.perform_admin_logout_and_reset()  # Call the safe, centralized reset function
            else:
                messagebox.showerror("Error", "Update failed (maybe username taken).", parent=win)

        ctk.CTkButton(win, text="Update Credentials", command=do_change, width=160).pack(pady=16)

    def show_user_dashboard(self):
        self.clear()
        self.title("User Dashboard")

        # ===== Menubar =====
        menubar = Menu(self)

        # --- Account Menu ---
        account_menu = Menu(menubar, tearoff=0)
        account_menu.add_command(label="Change Credentials", command=self.open_user_change)
        menubar.add_cascade(label="Account", menu=account_menu)

        # --- Help Menu ---
        help_menu = Menu(menubar, tearoff=0)

        def show_about():
            messagebox.showinfo(
                "About",
                "Secure License Activation System\n"
                "Version 1.0 (FYP Project 2025)\n\n"
                "Developed by:\n"
                "• Mohamad Faidhi Bin Ahmad Fauzil (21DDT23F1141)\n"
                "• Nur Azurin Binti Mohd Radzi (21DDT23F1097)\n"
                "• Nur Umairah Binti Mohd Sabri (21DDT23F1099)\n\n"
                "Supervised by: TS. Anirah Binti Ahmad\n"
                "Institution: Politeknik Balik Pulau",
                parent=self
            )

        help_menu.add_command(label="About", command=show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        # --- Logout ---
        menubar.add_command(label="Logout", command=self.perform_user_logout_and_reset)

        self.config(menu=menubar)

        # ===== Welcome Section =====
        # MODIFIED: Configure grid to center content
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        main_frame = ctk.CTkFrame(self, fg_color="transparent")
        main_frame.grid(row=0, column=0)

        ctk.CTkLabel(main_frame, text=f"Welcome, {self.current_user}", font=("Segoe UI", 20, "bold")).pack(pady=20,
                                                                                                           padx=20)
        ctk.CTkLabel(main_frame, text="Use the 'Account' menu above to manage your credentials.",
                     font=("Segoe UI", 13)).pack(
            pady=10, padx=20)

    def open_user_change(self):
        """Popup window for users to change their username/password"""
        win = ctk.CTkToplevel(self)
        win.title("Change Username / Password")
        win.geometry("420x380")
        win.resizable(False, False)  # This window should not be resizable
        win.transient(self)  # Keep it on top
        win.grab_set()  # Modal behavior

        ctk.CTkLabel(win, text="Change Your Account Details", font=("Segoe UI", 15, "bold")).pack(pady=(12, 8))
        ctk.CTkLabel(win, text="New Username", anchor="w").pack(padx=20, pady=(8, 2), fill="x")
        entry_new_user = ctk.CTkEntry(win, width=300)
        entry_new_user.insert(0, self.current_user)
        entry_new_user.pack(padx=20)
        ctk.CTkLabel(win, text="New Password", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_new_pw = ctk.CTkEntry(win, width=300, show="*")
        entry_new_pw.pack(padx=20)
        ctk.CTkLabel(win, text="Confirm New Password", anchor="w").pack(padx=20, pady=(10, 2), fill="x")
        entry_new_pw2 = ctk.CTkEntry(win, width=300, show="*")
        entry_new_pw2.pack(padx=20)

        def do_change():
            new_user = entry_new_user.get().strip()
            new_pw = entry_new_pw.get().strip()
            new_pw2 = entry_new_pw2.get().strip()

            if not new_user or not new_pw:
                messagebox.showwarning("Warning", "Please fill all fields.", parent=win)
                return
            if new_pw != new_pw2:
                messagebox.showwarning("Warning", "Passwords do not match.", parent=win)
                return

            ok = change_credentials(self.current_user, new_user, new_pw)
            if ok:
                messagebox.showinfo("Success", "Account updated. Please login again.", parent=win)
                win.destroy()  # Destroy this popup
                self.perform_user_logout_and_reset()  # Call the safe, centralized reset function
            else:
                messagebox.showerror("Error", "Update failed (maybe username taken).", parent=win)

        ctk.CTkButton(win, text="Update Account", command=do_change, width=160).pack(pady=16)

    # --- END: NEW AND UPDATED METHODS ---


# ----------------- Program entry -----------------
# MODIFIED: New startup logic (SECURITY FIX) ---
if __name__ == "__main__":

    # 1. Check if the license is valid on startup
    is_license_valid = check_license()

    if is_license_valid:
        # 2. License is valid, launch the main app
        init_db()
        app = App()
        app.mainloop()
    else:
        # 3. License is invalid or missing, show the activation window
        run_activation_window()

        # 4. After activation window closes, check one more time
        is_license_valid = check_license()

        if is_license_valid:
            # 5. Activation was successful, launch the main app
            init_db()
            app = App()
            # Show a success message *after* the app is created
            messagebox.showinfo("Activated", "Software activated. You can continue using the program.", parent=app)
            app.mainloop()
        else:
            # 6. Activation failed or was cancelled, exit
            print("Activation required. Exiting.")
            sys.exit(0)
#END MODIFIED