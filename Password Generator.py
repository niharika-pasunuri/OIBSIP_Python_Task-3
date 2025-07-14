import tkinter as tk
from tkinter import messagebox
import random
import string
import pyperclip

def generate_password():
    length = length_var.get()
    use_upper = upper_var.get()
    use_lower = lower_var.get()
    use_digits = digit_var.get()
    use_symbols = symbol_var.get()

    if not (use_upper or use_lower or use_digits or use_symbols):
        messagebox.showwarning("Warning", "Please select at least one character type.")
        return

    characters = ""
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    password = ''.join(random.choice(characters) for _ in range(length))
    password_var.set(password)
    assess_strength(password)

def copy_password():
    pwd = password_var.get()
    if pwd:
        pyperclip.copy(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard!")
    else:
        messagebox.showwarning("Warning", "No password to copy.")

def assess_strength(pwd):
    strength = "Weak"
    if len(pwd) >= 12:
        criteria = 0
        if any(c.islower() for c in pwd):
            criteria += 1
        if any(c.isupper() for c in pwd):
            criteria += 1
        if any(c.isdigit() for c in pwd):
            criteria += 1
        if any(c in string.punctuation for c in pwd):
            criteria += 1

        if criteria == 4:
            strength = "Strong"
        elif criteria == 3:
            strength = "Medium"
        else:
            strength = "Weak"
    else:
        strength = "Too Short"

    strength_var.set(f"Password Strength: {strength}")

# GUI Setup
root = tk.Tk()
root.title("Password Generator")
root.geometry("450x500")
root.config(bg="#e3f2fd")

# Title
title = tk.Label(root, text="🔐 Password Generator", font=("Segoe UI", 20, "bold"), bg="#e3f2fd", fg="#1a237e")
title.pack(pady=20)

frame = tk.Frame(root, bg="#e3f2fd")
frame.pack(pady=10)

# Length
length_var = tk.IntVar(value=12)
tk.Label(frame, text="Password Length:", bg="#e3f2fd", font=("Segoe UI", 14)).grid(row=0, column=0, sticky="e", padx=10, pady=5)
tk.Spinbox(frame, from_=4, to=32, textvariable=length_var, width=5, font=("Segoe UI", 14)).grid(row=0, column=1, sticky="w", pady=5)

# Character Options
upper_var = tk.BooleanVar(value=True)
lower_var = tk.BooleanVar(value=True)
digit_var = tk.BooleanVar(value=True)
symbol_var = tk.BooleanVar(value=True)

options_font = ("Segoe UI", 13)
tk.Checkbutton(frame, text="Uppercase Letters (A-Z)", variable=upper_var, bg="#e3f2fd", font=options_font).grid(row=1, column=0, columnspan=2, sticky="w")
tk.Checkbutton(frame, text="Lowercase Letters (a-z)", variable=lower_var, bg="#e3f2fd", font=options_font).grid(row=2, column=0, columnspan=2, sticky="w")
tk.Checkbutton(frame, text="Digits (0-9)", variable=digit_var, bg="#e3f2fd", font=options_font).grid(row=3, column=0, columnspan=2, sticky="w")
tk.Checkbutton(frame, text="Symbols (!@#...)", variable=symbol_var, bg="#e3f2fd", font=options_font).grid(row=4, column=0, columnspan=2, sticky="w")

# Generate button
tk.Button(root, text="Generate Password", command=generate_password, bg="#1565c0", fg="white", font=("Segoe UI", 14, "bold"), width=20).pack(pady=20)

# Result display
password_var = tk.StringVar()
tk.Entry(root, textvariable=password_var, font=("Segoe UI", 14), justify="center", width=30).pack(pady=10)

# Strength label
strength_var = tk.StringVar()
tk.Label(root, textvariable=strength_var, bg="#e3f2fd", font=("Segoe UI", 13, "bold"), fg="#424242").pack(pady=5)

# Copy button
tk.Button(root, text="Copy to Clipboard", command=copy_password, bg="#2e7d32", fg="white", font=("Segoe UI", 14, "bold"), width=20).pack(pady=10)

root.mainloop()