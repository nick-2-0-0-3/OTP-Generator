import json
import base64
import os
import pyotp
import time
from pathlib import Path
from tkinter import BooleanVar, filedialog
import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from platformdirs import user_config_dir


# =========================
# CONFIG / STORAGE
# =========================

CONFIG_DIR = Path(user_config_dir()) / "OTP Generator"
DATA_FILE = CONFIG_DIR / "otps.enc"
KEY_FILE = CONFIG_DIR / "key.key"


def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_or_create_key():
    ensure_config_dir()

    if KEY_FILE.exists():
        return KEY_FILE.read_bytes()

    key = Fernet.generate_key()
    KEY_FILE.write_bytes(key)
    return key


def get_fernet():
    return Fernet(load_or_create_key())


def derive_password_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_secret_with_password(secret, password):
    salt = os.urandom(16)
    password_key = derive_password_key(password, salt)
    encrypted_secret = Fernet(password_key).encrypt(secret.encode("utf-8")).decode("utf-8")
    return encrypted_secret, base64.b64encode(salt).decode("utf-8")


def decrypt_secret_with_password(item, password):
    salt_b64 = item.get("password_salt", "")
    encrypted_secret = item.get("secret_encrypted", "")

    if not salt_b64 or not encrypted_secret:
        raise InvalidToken

    salt = base64.b64decode(salt_b64.encode("utf-8"))
    password_key = derive_password_key(password, salt)
    return Fernet(password_key).decrypt(encrypted_secret.encode("utf-8")).decode("utf-8")


def normalize_saved_otp_item(item):
    if not isinstance(item, dict):
        return None

    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        return None

    if isinstance(item.get("secret"), str) and item["secret"].strip():
        return {
            "name": name.strip(),
            "secret": item["secret"].strip()
        }

    encrypted_secret = item.get("secret_encrypted")
    password_salt = item.get("password_salt")
    if isinstance(encrypted_secret, str) and encrypted_secret and isinstance(password_salt, str) and password_salt:
        return {
            "name": name.strip(),
            "secret_encrypted": encrypted_secret,
            "password_salt": password_salt
        }

    return None


def get_storage_ready_saved_otps():
    items_to_store = []

    for item in saved_otps:
        normalized_item = normalize_saved_otp_item(item)
        if normalized_item is not None:
            items_to_store.append(normalized_item)

    return items_to_store


def load_saved_otps_from_disk():
    ensure_config_dir()

    if not DATA_FILE.exists():
        return []

    try:
        encrypted_data = DATA_FILE.read_bytes()
        decrypted_data = get_fernet().decrypt(encrypted_data)
        data = json.loads(decrypted_data.decode("utf-8"))

        if isinstance(data, list):
            normalized_items = []
            for item in data:
                normalized_item = normalize_saved_otp_item(item)
                if normalized_item is not None:
                    normalized_items.append(normalized_item)
            return normalized_items
        return []
    except Exception as e:
        print(f"Fehler beim Laden der OTPs: {e}")
        return []


def save_saved_otps_to_disk():
    try:
        json_data = json.dumps(get_storage_ready_saved_otps(), ensure_ascii=False, indent=2).encode("utf-8")
        encrypted_data = get_fernet().encrypt(json_data)
        DATA_FILE.write_bytes(encrypted_data)
    except Exception as e:
        print(f"Fehler beim Speichern der OTPs: {e}")


def build_saved_otp_item(name, secret, password=""):
    if password:
        encrypted_secret, password_salt = encrypt_secret_with_password(secret, password)
        return {
            "name": name,
            "secret_encrypted": encrypted_secret,
            "password_salt": password_salt
        }

    return {
        "name": name,
        "secret": secret
    }


def add_saved_otp(name, secret, password=""):
    global saved_otps

    saved_otps.append(build_saved_otp_item(name, secret, password))
    save_saved_otps_to_disk()


def delete_saved_otp(index):
    global saved_otps

    if 0 <= index < len(saved_otps):
        saved_otps.pop(index)
        save_saved_otps_to_disk()


# =========================
# OTP LOGIC
# =========================

def generate_otp(secret):
    try:
        totp = pyotp.TOTP(secret)
        return totp.now(), totp.interval - (int(time.time()) % totp.interval)
    except Exception:
        return None, None


def update_progress_bar(progress_bar):
    interval = 30
    progress_value = (time.time() % interval) / interval
    progress_bar.set(progress_value)

    if progress_value >= 0.8:
        progress_bar.configure(progress_color=("#a5761f"))
    else:
        progress_bar.configure(progress_color=("#1f6aa5"))


def reset_progress_bar(progress_bar):
    progress_bar.set(0)
    progress_bar.configure(progress_color=("#1f6aa5"))


def render_otp():
    secret = entry_secret.get().strip()

    if secret == "":
        entry_otp.configure(state="normal")
        entry_otp.delete(0, "end")
        entry_otp.configure(state="readonly")
        reset_progress_bar(progress_otp)
        return

    otp, _ = generate_otp(secret)

    if otp is not None:
        entry_otp.configure(state="normal")
        entry_otp.delete(0, "end")
        entry_otp.insert(0, otp)
        entry_otp.configure(state="readonly")
        update_progress_bar(progress_otp)

    else:
        entry_otp.configure(state="normal")
        entry_otp.delete(0, "end")
        entry_otp.insert(0, "Invalid Secret")
        entry_otp.configure(state="readonly")
        reset_progress_bar(progress_otp)


def paste_secret():
    try:
        clipboard_text = gui.clipboard_get()
    except Exception:
        clipboard_text = ""

    entry_secret.delete(0, "end")
    entry_secret.insert(0, clipboard_text)
    render_otp()


def copy_otp():
    otp_value = entry_otp.get().strip()
    if otp_value and otp_value != "Invalid Secret":
        gui.clipboard_clear()
        gui.clipboard_append(otp_value)


def clear_secret():
    entry_secret.delete(0, "end")
    render_otp()


# =========================
# SAVED TAB LOGIC
# =========================

saved_otps = []
saved_otp_widgets = []
saved_edit_mode = False
unlocking_otp_index = None


def is_password_protected(item):
    return "secret_encrypted" in item and "password_salt" in item


def get_item_secret(item):
    if "secret" in item:
        return item["secret"]
    return item.get("_unlocked_secret")


def unlock_saved_otp(index, password):
    item = saved_otps[index]
    secret = decrypt_secret_with_password(item, password)
    item["_unlocked_secret"] = secret
    return secret


def lock_saved_otp(index):
    item = saved_otps[index]
    item.pop("_unlocked_secret", None)
    cancel_unlock_saved_otp()
    rebuild_saved_otps()


def update_saved_otp(index, name, secret, password=""):
    saved_otps[index] = build_saved_otp_item(name, secret, password)
    save_saved_otps_to_disk()


def open_edit_otp_window(index):
    item = saved_otps[index]
    protected_item = is_password_protected(item)

    edit_window = ctk.CTkToplevel(gui)
    edit_window.title("Edit OTP")
    edit_window.geometry("330x520")
    edit_window.resizable(False, False)
    edit_window.lift()
    edit_window.focus()

    label_name = ctk.CTkLabel(edit_window, text="Name:")
    label_name.pack(anchor="w", padx=15, pady=(15, 5))

    entry_name = ctk.CTkEntry(edit_window, width=300)
    entry_name.pack(padx=15)
    entry_name.insert(0, item["name"])

    unlock_state = {
        "secret": item["secret"] if not protected_item else None,
        "old_password": None,
    }

    if protected_item:
        label_old_password = ctk.CTkLabel(edit_window, text="Old Password:")
        label_old_password.pack(anchor="w", padx=15, pady=(10, 5))

        unlock_row = ctk.CTkFrame(edit_window, fg_color="transparent")
        unlock_row.pack(fill="x", padx=15)

        entry_old_password = ctk.CTkEntry(unlock_row, width=220, show="*")
        entry_old_password.pack(side="left")

        def unlock_for_edit():
            old_password = entry_old_password.get()
            if not old_password:
                label_error.configure(text="Please enter the old password.")
                return

            try:
                unlock_state["secret"] = decrypt_secret_with_password(item, old_password)
            except Exception:
                label_error.configure(text="Old password is incorrect.")
                return

            unlock_state["old_password"] = old_password
            entry_secret.configure(state="normal")
            entry_secret.delete(0, "end")
            entry_secret.insert(0, unlock_state["secret"])
            entry_new_password.configure(state="normal")
            entry_confirm_password.configure(state="normal")
            button_unlock_secret.configure(state="disabled")
            entry_old_password.configure(state="disabled")
            label_error.configure(text="")

        button_unlock_secret = ctk.CTkButton(
            unlock_row,
            text="Unlock",
            width=70,
            fg_color="#39863c",
            hover_color="#2A5E2A",
            command=unlock_for_edit
        )
        button_unlock_secret.pack(side="right")

    label_secret_saved = ctk.CTkLabel(edit_window, text="Secret:")
    label_secret_saved.pack(anchor="w", padx=15, pady=(10, 5))

    entry_secret = ctk.CTkEntry(edit_window, width=300)
    entry_secret.pack(padx=15)

    if unlock_state["secret"] is not None:
        entry_secret.insert(0, unlock_state["secret"])
    else:
        entry_secret.configure(state="disabled")

    label_new_password = ctk.CTkLabel(edit_window, text="New Password (optional):")
    label_new_password.pack(anchor="w", padx=15, pady=(10, 5))

    entry_new_password = ctk.CTkEntry(edit_window, width=300, show="*")
    entry_new_password.pack(padx=15)
    if protected_item and unlock_state["secret"] is None:
        entry_new_password.configure(state="disabled")

    label_confirm_password = ctk.CTkLabel(edit_window, text="Confirm New Password:")
    label_confirm_password.pack(anchor="w", padx=15, pady=(10, 5))

    entry_confirm_password = ctk.CTkEntry(edit_window, width=300, show="*")
    entry_confirm_password.pack(padx=15)
    if protected_item and unlock_state["secret"] is None:
        entry_confirm_password.configure(state="disabled")

    remove_password_var = BooleanVar(value=False)

    if protected_item:
        checkbox_remove_password = ctk.CTkCheckBox(
            edit_window,
            text="Remove password protection",
            variable=remove_password_var
        )
        checkbox_remove_password.pack(anchor="w", padx=15, pady=(10, 0))

        label_password_hint = ctk.CTkLabel(
            edit_window,
            text="Leave the new password fields empty to keep the current password.",
            text_color="gray",
            wraplength=290,
            justify="left"
        )
        label_password_hint.pack(anchor="w", padx=15, pady=(4, 0))

    label_error = ctk.CTkLabel(
        edit_window,
        text="",
        text_color="#d32f2f",
        wraplength=290,
        justify="left"
    )
    label_error.pack(anchor="w", padx=15, pady=(8, 0))

    def on_save():
        name = entry_name.get().strip()
        secret = entry_secret.get().strip()
        new_password = entry_new_password.get()
        confirm_password = entry_confirm_password.get()

        if not name:
            label_error.configure(text="Name is required.")
            return

        if protected_item and unlock_state["secret"] is None:
            label_error.configure(text="Please unlock the OTP first.")
            return

        if not secret:
            label_error.configure(text="Secret is required.")
            return

        if protected_item and remove_password_var.get() and (new_password or confirm_password):
            label_error.configure(text="Clear the new password fields to remove the password.")
            return

        if new_password != confirm_password:
            label_error.configure(text="New passwords do not match.")
            return

        otp, _ = generate_otp(secret)
        if otp is None:
            label_error.configure(text="Secret is invalid.")
            return

        password_to_store = new_password
        if protected_item:
            if remove_password_var.get():
                password_to_store = ""
            elif not new_password:
                password_to_store = unlock_state["old_password"]

        update_saved_otp(index, name, secret, password_to_store)
        rebuild_saved_otps()
        edit_window.destroy()

    button_frame = ctk.CTkFrame(edit_window, fg_color="transparent")
    button_frame.pack(fill="x", padx=15, pady=(0, 15), side="bottom")

    bottom_spacer = ctk.CTkFrame(edit_window, fg_color="transparent")
    bottom_spacer.pack(fill="both", expand=True)

    button_cancel = ctk.CTkButton(
        button_frame,
        text="Cancel",
        width=100,
        command=edit_window.destroy
    )
    button_cancel.pack(side="left", padx=(20, 0))

    button_save = ctk.CTkButton(
        button_frame,
        text="Save",
        width=100,
        fg_color="#39863c",
        hover_color="#2A5E2A",
        command=on_save
    )
    button_save.pack(side="right", padx=(0, 20))

    if protected_item and unlock_state["secret"] is None:
        entry_old_password.focus()
        entry_old_password.bind("<Return>", lambda e: unlock_for_edit())
    else:
        entry_name.focus()

    edit_window.grab_set()


def start_unlock_saved_otp(index):
    global unlocking_otp_index

    unlocking_otp_index = index
    rebuild_saved_otps()


def cancel_unlock_saved_otp():
    global unlocking_otp_index

    unlocking_otp_index = None
    rebuild_saved_otps()


def submit_unlock_saved_otp(index, password):
    global unlocking_otp_index

    if not password:
        cancel_unlock_saved_otp()
        return

    try:
        unlock_saved_otp(index, password)
    except Exception:
        return

    unlocking_otp_index = None
    rebuild_saved_otps()


def handle_unlock_button_click(index, password=""):
    if unlocking_otp_index == index:
        if password.strip():
            submit_unlock_saved_otp(index, password)
        else:
            cancel_unlock_saved_otp()
    else:
        start_unlock_saved_otp(index)


def confirm_delete_otp(index, name):
    confirm_window = ctk.CTkToplevel(gui)
    confirm_window.title("Delete OTP")
    confirm_window.geometry("340x150")
    confirm_window.resizable(False, False)
    confirm_window.lift()
    confirm_window.focus()

    label_text = ctk.CTkLabel(
        confirm_window,
        text=f"Delete '{name}'?",
        anchor="center",
        font=("", 14, "bold")
    )
    label_text.pack(padx=20, pady=(20, 8))

    label_info = ctk.CTkLabel(
        confirm_window,
        text="This action cannot be undone.",
        anchor="center",
        text_color="gray"
    )
    label_info.pack(padx=20, pady=(0, 15))

    def on_confirm():
        delete_and_refresh(index)
        confirm_window.destroy()

    button_frame = ctk.CTkFrame(confirm_window, fg_color="transparent")
    button_frame.pack(fill="x", padx=20, pady=(0, 15), side="bottom")

    bottom_spacer = ctk.CTkFrame(confirm_window, fg_color="transparent")
    bottom_spacer.pack(fill="both", expand=True)

    cancel_button = ctk.CTkButton(
        button_frame,
        text="Cancel",
        width=100,
        command=confirm_window.destroy
    )
    cancel_button.pack(side="left", expand=True, padx=5)

    delete_button = ctk.CTkButton(
        button_frame,
        text="Delete",
        width=100,
        fg_color="#d32f2f",
        hover_color="#b71c1c",
        command=on_confirm
    )
    delete_button.pack(side="right", expand=True, padx=5)

    confirm_window.grab_set()


def delete_and_refresh(index):
    delete_saved_otp(index)
    rebuild_saved_otps()


def delete_all_saved_otps():
    global saved_otps

    saved_otps = []
    save_saved_otps_to_disk()
    rebuild_saved_otps()


def confirm_delete_all_otps():
    if not saved_otps:
        return

    confirm_window = ctk.CTkToplevel(gui)
    confirm_window.title("Delete All OTPs")
    confirm_window.geometry("340x150")
    confirm_window.resizable(False, False)
    confirm_window.lift()
    confirm_window.focus()

    label_text = ctk.CTkLabel(
        confirm_window,
        text="Delete all OTPs?",
        anchor="center",
        font=("", 14, "bold")
    )
    label_text.pack(padx=20, pady=(20, 8))

    label_info = ctk.CTkLabel(
        confirm_window,
        text="This action cannot be undone.",
        anchor="center",
        text_color="gray"
    )
    label_info.pack(padx=20, pady=(0, 15))

    def on_confirm():
        delete_all_saved_otps()
        confirm_window.destroy()

    button_frame = ctk.CTkFrame(confirm_window, fg_color="transparent")
    button_frame.pack(fill="x", padx=20, pady=(0, 15), side="bottom")

    bottom_spacer = ctk.CTkFrame(confirm_window, fg_color="transparent")
    bottom_spacer.pack(fill="both", expand=True)

    cancel_button = ctk.CTkButton(
        button_frame,
        text="Cancel",
        width=100,
        command=confirm_window.destroy
    )
    cancel_button.pack(side="left", expand=True, padx=5)

    delete_button = ctk.CTkButton(
        button_frame,
        text="Delete",
        width=100,
        fg_color="#d32f2f",
        hover_color="#b71c1c",
        command=on_confirm
    )
    delete_button.pack(side="right", expand=True, padx=5)

    confirm_window.grab_set()


def validate_imported_otps(data):
    valid_otps = []

    if not isinstance(data, list):
        return valid_otps

    for item in data:
        normalized_item = normalize_saved_otp_item(item)
        if normalized_item is not None:
            valid_otps.append(normalized_item)

    return valid_otps


def export_saved_otps():
    if not saved_otps:
        return

    file_path = filedialog.asksaveasfilename(
        title="Export OTPs",
        defaultextension=".json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )

    if not file_path:
        return

    try:
        Path(file_path).write_text(
            json.dumps(get_storage_ready_saved_otps(), ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except Exception as e:
        print(f"Fehler beim Exportieren der OTPs: {e}")


def import_saved_otps():
    global saved_otps

    file_path = filedialog.askopenfilename(
        title="Import OTPs",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )

    if not file_path:
        return

    try:
        imported_data = json.loads(Path(file_path).read_text(encoding="utf-8"))
        valid_otps = validate_imported_otps(imported_data)

        if not valid_otps:
            return

        saved_otps = valid_otps
        save_saved_otps_to_disk()
        rebuild_saved_otps()
    except Exception as e:
        print(f"Fehler beim Importieren der OTPs: {e}")


def move_saved_otp(old_index, new_index):
    global saved_otps

    if not (0 <= old_index < len(saved_otps) and 0 <= new_index < len(saved_otps)):
        return

    item = saved_otps.pop(old_index)
    saved_otps.insert(new_index, item)
    save_saved_otps_to_disk()
    rebuild_saved_otps()


def toggle_saved_edit_mode():
    global saved_edit_mode

    saved_edit_mode = not saved_edit_mode
    if saved_edit_mode:
        button_edit_saved.configure(
            text="Done",
            fg_color="#39863c",
            hover_color="#2e6b31"
        )
    else:
        button_edit_saved.configure(
            text="Edit",
            fg_color=ctk.ThemeManager.theme["CTkButton"]["fg_color"],
            hover_color=ctk.ThemeManager.theme["CTkButton"]["hover_color"]
        )
    update_saved_actions_visibility()
    rebuild_saved_otps()


def copy_saved_otp(secret):
    otp, _ = generate_otp(secret)
    if otp:
        gui.clipboard_clear()
        gui.clipboard_append(otp)


def update_saved_actions_visibility():
    if saved_edit_mode:
        saved_actions_frame.pack(fill="x", padx=6, pady=(10, 0))
    else:
        saved_actions_frame.pack_forget()


def rebuild_saved_otps():
    global saved_otp_widgets

    for widget in saved_list_frame.winfo_children():
        widget.destroy()

    saved_otp_widgets = []

    if not saved_otps:
        empty_label = ctk.CTkLabel(saved_list_frame, text="No OTPs saved yet")
        empty_label.pack(pady=20)
        return

    for index, item in enumerate(saved_otps):
        row = ctk.CTkFrame(saved_list_frame)
        row.pack(fill="x", pady=5)

        if saved_edit_mode:
            move_frame = ctk.CTkFrame(row, fg_color="transparent")
            move_frame.pack(side="left", padx=(10, 0))

            button_up = ctk.CTkButton(
                move_frame,
                text="↑",
                width=28,
                height=18,
                fg_color="transparent",
                bg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray80", "gray25"),
                border_width=0,
                command=lambda i=index: move_saved_otp(i, i - 1)
            )
            button_up.pack(pady=(0, 0))
            if index == 0:
                button_up.configure(state="disabled")

            button_down = ctk.CTkButton(
                move_frame,
                text="↓",
                width=28,
                height=18,
                fg_color="transparent",
                bg_color="transparent",
                text_color=("gray10", "gray90"),
                hover_color=("gray80", "gray25"),
                border_width=0,
                command=lambda i=index: move_saved_otp(i, i + 1)
            )
            button_down.pack(pady=(0, 0))
            if index == len(saved_otps) - 1:
                button_down.configure(state="disabled")

        left_frame = ctk.CTkFrame(row, fg_color="transparent")
        left_frame.pack(side="left", fill="x", expand=True, padx=15, pady=2)

        label_name = ctk.CTkLabel(
            left_frame,
            text=item["name"],
            anchor="w",
            font=("", 15, "bold"),
            height=22
        )
        label_name.pack(anchor="w", pady=(5, 0))

        label_otp = ctk.CTkLabel(
            left_frame,
            text="",
            anchor="w",
            font=("", 14, "normal"),
            height=22
        )
        label_otp.pack(anchor="w", pady=(0, 5))

        entry_unlock_password = None

        if not saved_edit_mode and is_password_protected(item) and get_item_secret(item) is None and unlocking_otp_index == index:
            action_frame = ctk.CTkFrame(row, fg_color="transparent")
            action_frame.pack(side="right", padx=(5, 15), pady=2)

            unlock_inline_frame = ctk.CTkFrame(action_frame, fg_color="transparent")
            unlock_inline_frame.pack(side="left", padx=(0, 8))

            unlock_input_row = ctk.CTkFrame(unlock_inline_frame, fg_color="transparent")
            unlock_input_row.pack(anchor="e")

            entry_unlock_password = ctk.CTkEntry(
                unlock_input_row,
                width=110,
                height=28,
                show="*"
            )
            entry_unlock_password.pack(side="left")

        if not saved_edit_mode:
            if not (is_password_protected(item) and get_item_secret(item) is None and unlocking_otp_index == index):
                action_frame = ctk.CTkFrame(row, fg_color="transparent")
                action_frame.pack(side="right", padx=(5, 15), pady=2)

            if is_password_protected(item) and get_item_secret(item) is None:
                button_unlock = ctk.CTkButton(
                    action_frame,
                    text="🔒",
                    width=34,
                    height=34,
                    font=("", 18),
                    fg_color="transparent",
                    bg_color="transparent",
                    hover_color=("gray80", "gray25"),
                    text_color=("gray10", "gray90"),
                    border_width=0,
                    command=lambda i=index, entry_ref=entry_unlock_password: handle_unlock_button_click(
                        i,
                        entry_ref.get() if entry_ref is not None else ""
                    )
                )
                button_unlock.pack(side="right")
            else:
                button_copy = ctk.CTkButton(
                    action_frame,
                    text="⧉",
                    width=34,
                    height=34,
                    font=("", 18),
                    fg_color="transparent",
                    bg_color="transparent",
                    hover_color=("gray80", "gray25"),
                    text_color=("gray10", "gray90"),
                    border_width=0,
                    command=lambda i=index: copy_saved_otp(get_item_secret(saved_otps[i]))
                )
                button_copy.pack(side="right")

                if is_password_protected(item):
                    button_lock = ctk.CTkButton(
                        action_frame,
                        text="🔒",
                        width=34,
                        height=34,
                        font=("", 18),
                        fg_color="transparent",
                        bg_color="transparent",
                        hover_color=("gray80", "gray25"),
                        text_color=("gray10", "gray90"),
                        border_width=0,
                        command=lambda i=index: lock_saved_otp(i)
                    )
                    button_lock.pack(side="right", padx=(0, 6))

        if saved_edit_mode:
            button_delete = ctk.CTkButton(
                row,
                text="✕",
                width=34,
                height=34,
                font=("", 18),
                fg_color="transparent",
                bg_color="transparent",
                hover_color=("gray80", "gray25"),
                text_color="#d32f2f",
                border_width=0,
                command=lambda i=index, name=item["name"]: confirm_delete_otp(i, name)
            )
            button_delete.pack(side="right", padx=(5, 15))

            button_edit_item = ctk.CTkButton(
                row,
                text="≡",
                width=34,
                height=34,
                font=("", 18),
                fg_color="transparent",
                bg_color="transparent",
                hover_color=("gray80", "gray25"),
                text_color=("gray10", "gray90"),
                border_width=0,
                command=lambda i=index: open_edit_otp_window(i)
            )
            button_edit_item.pack(side="right")

        saved_otp_widgets.append({
            "label_name": label_name,
            "label_otp": label_otp,
            "entry_unlock_password": entry_unlock_password,
            "index": index,
            "last_text": None,
        })

    update_saved_otp_labels()

    if unlocking_otp_index is not None:
        for widget_info in saved_otp_widgets:
            if widget_info["index"] == unlocking_otp_index and widget_info["entry_unlock_password"] is not None:
                widget_info["entry_unlock_password"].focus()
                widget_info["entry_unlock_password"].bind(
                    "<Return>",
                    lambda e, i=unlocking_otp_index, entry_ref=widget_info["entry_unlock_password"]: submit_unlock_saved_otp(i, entry_ref.get())
                )
                break


def update_saved_otp_labels():
    if len(saved_otps) != len(saved_otp_widgets):
        rebuild_saved_otps()
        return

    for i, item in enumerate(saved_otps):
        secret = get_item_secret(item)
        if is_password_protected(item) and secret is None:
            subtext = "Locked"
        else:
            otp, _ = generate_otp(secret)
            subtext = otp if otp is not None else "Invalid Secret"

        if saved_otp_widgets[i]["last_text"] != subtext:
            saved_otp_widgets[i]["label_otp"].configure(text=subtext)
            saved_otp_widgets[i]["last_text"] = subtext


def open_add_otp_window(prefill_secret=""):
    add_window = ctk.CTkToplevel(gui)
    add_window.title("Add OTP")
    add_window.geometry("330x380")
    add_window.resizable(False, False)
    add_window.lift()
    add_window.focus()

    label_name = ctk.CTkLabel(add_window, text="Name:")
    label_name.pack(anchor="w", padx=15, pady=(15, 5))

    entry_name = ctk.CTkEntry(add_window, width=300)
    entry_name.pack(padx=15)

    label_secret_saved = ctk.CTkLabel(add_window, text="Secret:")
    label_secret_saved.pack(anchor="w", padx=15, pady=(10, 5))

    entry_secret_saved = ctk.CTkEntry(add_window, width=300)
    entry_secret_saved.pack(padx=15)

    if prefill_secret:
        entry_secret_saved.insert(0, prefill_secret)

    label_password_saved = ctk.CTkLabel(add_window, text="Password (optional):")
    label_password_saved.pack(anchor="w", padx=15, pady=(10, 5))

    entry_password_saved = ctk.CTkEntry(add_window, width=300, show="*")
    entry_password_saved.pack(padx=15)

    label_password_confirm_saved = ctk.CTkLabel(add_window, text="Confirm Password:")
    label_password_confirm_saved.pack(anchor="w", padx=15, pady=(10, 5))

    entry_password_confirm_saved = ctk.CTkEntry(add_window, width=300, show="*")
    entry_password_confirm_saved.pack(padx=15)

    label_add_error = ctk.CTkLabel(add_window, text="", text_color="#d32f2f")
    label_add_error.pack(anchor="w", padx=15, pady=(8, 0))

    def save_new_otp():
        name = entry_name.get().strip()
        secret = entry_secret_saved.get().strip()
        password = entry_password_saved.get()
        password_confirm = entry_password_confirm_saved.get()

        if not name or not secret:
            label_add_error.configure(text="Name and secret are required.")
            return

        otp, _ = generate_otp(secret)
        if otp is None:
            label_add_error.configure(text="Secret is invalid.")
            return

        if password != password_confirm:
            label_add_error.configure(text="Passwords do not match.")
            return

        if password_confirm and not password:
            label_add_error.configure(text="Please enter the password in both fields.")
            return

        add_saved_otp(name, secret, password=password)
        rebuild_saved_otps()
        add_window.destroy()

    button_frame = ctk.CTkFrame(add_window, fg_color="transparent")
    button_frame.pack(fill="x", padx=15, pady=(0, 15), side="bottom")

    bottom_spacer = ctk.CTkFrame(add_window, fg_color="transparent")
    bottom_spacer.pack(fill="both", expand=True)

    button_cancel = ctk.CTkButton(
        button_frame,
        text="Cancel",
        width=100,
        command=add_window.destroy
    )
    button_cancel.pack(side="left", padx=(20, 0))

    button_save = ctk.CTkButton(
        button_frame,
        text="Save",
        width=100,
        command=save_new_otp,
        fg_color="#39863c",
        hover_color="#2A5E2A"
    )
    button_save.pack(side="right", padx=(0, 20))

    entry_name.focus()
    add_window.grab_set()


def update_generator_loop():
    render_otp()
    gui.after(10, update_generator_loop)


def update_saved_loop():
    update_saved_otp_labels()
    if saved_otps:
        update_progress_bar(progress_saved_otp)
    else:
        reset_progress_bar(progress_saved_otp)
    gui.after(10, update_saved_loop)


# =========================
# GUI
# =========================

saved_otps = load_saved_otps_from_disk()

gui = ctk.CTk()
gui.geometry("360x400")
gui.title("OTP Generator")
gui.minsize(360, 340)
gui.maxsize(500, 800)

tabview = ctk.CTkTabview(gui, fg_color="transparent")
tabview.pack(padx=10, pady=10, fill="both", expand=True)

tab_saved = tabview.add("   OTP Storage   ")
tab_generator = tabview.add("  Live Generator  ")



# =========================
# GENERATOR TAB
# =========================

frame_secret_outline = ctk.CTkFrame(tab_generator, fg_color="transparent")
frame_secret_outline.pack(pady=(20, 0))

label_secret = ctk.CTkLabel(frame_secret_outline, text="Secret:")
label_secret.pack(anchor="nw", padx=5)

frame_secret = ctk.CTkFrame(frame_secret_outline)
frame_secret.pack()

entry_secret = ctk.CTkEntry(
    frame_secret,
    width=180,
    height=40,
    border_width=0,
    fg_color="transparent",
)
entry_secret.pack(side="left", padx=(5, 0))

button_paste_secret = ctk.CTkButton(
    frame_secret,
    text="Paste",
    width=95,
    height=30,
    command=paste_secret
)
button_paste_secret.pack(side="right", padx=5)

button_clear_secret = ctk.CTkButton(
    frame_secret,
    text="✖",
    width=20,
    height=40,
    fg_color="transparent",
    hover=False,
    text_color="grey",
    command=clear_secret
)
button_clear_secret.pack(side="right")

button_clear_secret.bind("<Enter>", lambda e: button_clear_secret.configure(text_color="white"))
button_clear_secret.bind("<Leave>", lambda e: button_clear_secret.configure(text_color="gray"))

frame_otp_outline = ctk.CTkFrame(tab_generator, fg_color="transparent")
frame_otp_outline.pack(pady=10)

label_otp = ctk.CTkLabel(frame_otp_outline, text="Current OTP:")
label_otp.pack(anchor="nw", padx=5)

frame_otp = ctk.CTkFrame(frame_otp_outline)
frame_otp.pack()

frame_otp_bottom = ctk.CTkFrame(frame_otp_outline)
frame_otp_bottom.pack(pady=(5, 0))

entry_otp = ctk.CTkEntry(
    frame_otp,
    width=210,
    height=40,
    state="readonly",
    fg_color="transparent",
    border_width=0
)
entry_otp.pack(side="left", padx=5)

entry_secret.bind("<KeyRelease>", lambda e: render_otp())

button_copy_otp = ctk.CTkButton(
    frame_otp,
    text="Copy",
    width=95,
    height=30,
    command=copy_otp
)
button_copy_otp.pack(side="right", padx=(0, 5))

progress_otp = ctk.CTkProgressBar(frame_otp_bottom, width=310)
progress_otp.pack(padx=5, pady=5, side="bottom", anchor="s")
progress_otp.set(0)

button_add_saved_from_generator = ctk.CTkButton(
    tab_generator,
    text="Add OTP",
    width=100,
    height=20,
    command=lambda: open_add_otp_window(entry_secret.get().strip())
)
button_add_saved_from_generator.pack(side="bottom")


# =========================
# SAVED TAB
# =========================

saved_top_section = ctk.CTkFrame(tab_saved, fg_color="transparent")
saved_top_section.pack(fill="x")

frame_saved_progress_outline = ctk.CTkFrame(saved_top_section, fg_color="transparent")
frame_saved_progress_outline.pack(fill="x", padx=6, pady=(10, 0))

frame_saved_progress = ctk.CTkFrame(frame_saved_progress_outline)
frame_saved_progress.pack()

progress_saved_otp = ctk.CTkProgressBar(frame_saved_progress, width=310)
progress_saved_otp.pack(padx=5, pady=5, side="bottom", anchor="s")
progress_saved_otp.set(0)

saved_actions_frame = ctk.CTkFrame(saved_top_section, fg_color="transparent")

saved_actions_inner = ctk.CTkFrame(saved_actions_frame, width=320, height=30)
saved_actions_inner.pack(anchor="center")
saved_actions_inner.pack_propagate(False)

saved_actions_buttons = ctk.CTkFrame(saved_actions_inner, fg_color="transparent")
saved_actions_buttons.place(relx=0.5, rely=0.5, anchor="center")

button_add_saved = ctk.CTkButton(
    saved_actions_buttons,
    text="Add OTP",
    width=68,
    height=20,
    command=open_add_otp_window
)
button_add_saved.pack(side="left", padx=(5, 0), pady=5)

button_export_saved = ctk.CTkButton(
    saved_actions_buttons,
    text="Export",
    width=68,
    height=20,
    command=export_saved_otps
)
button_export_saved.pack(side="left", padx=(10, 0), pady=5)

button_import_saved = ctk.CTkButton(
    saved_actions_buttons,
    text="Import",
    width=68,
    height=20,
    command=import_saved_otps
)
button_import_saved.pack(side="left", padx=(10, 0), pady=5)

button_delete_all_saved = ctk.CTkButton(
    saved_actions_buttons,
    text="Delete all",
    width=68,
    height=20,
    fg_color="#d32f2f",
    hover_color="#b71c1c",
    command=confirm_delete_all_otps
)
button_delete_all_saved.pack(side="left", padx=(10, 5), pady=5)

saved_list_frame = ctk.CTkScrollableFrame(tab_saved, fg_color="transparent")
saved_list_frame.pack(fill="both", expand=True)

saved_tab_bottom_controls = ctk.CTkFrame(tab_saved, fg_color="transparent")
saved_tab_bottom_controls.pack(fill="x", pady=(5, 0))

saved_tab_bottom_inner = ctk.CTkFrame(saved_tab_bottom_controls, fg_color="transparent")
saved_tab_bottom_inner.pack(anchor="center")

button_edit_saved = ctk.CTkButton(
    saved_tab_bottom_inner,
    text="Edit",
    width=100,
    height=20,
    command=toggle_saved_edit_mode
)
button_edit_saved.pack(side="left")

update_saved_actions_visibility()
rebuild_saved_otps()
render_otp()
update_generator_loop()
update_saved_loop()
gui.mainloop()
