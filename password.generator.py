import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

class PasswordGeneratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator")
        self.root.geometry("400x300")

        self.create_widgets()

    def create_widgets(self):
        # Password length label and entry
        self.label_length = ttk.Label(self.root, text="Password Length:")
        self.label_length.pack(pady=10)
        self.entry_length = ttk.Entry(self.root)
        self.entry_length.pack()

        # Checkbuttons for character set options
        self.include_letters = tk.BooleanVar()
        self.include_numbers = tk.BooleanVar()
        self.include_symbols = tk.BooleanVar()

        self.checkbutton_letters = ttk.Checkbutton(self.root, text="Include Letters", variable=self.include_letters)
        self.checkbutton_letters.pack(pady=5)

        self.checkbutton_numbers = ttk.Checkbutton(self.root, text="Include Numbers", variable=self.include_numbers)
        self.checkbutton_numbers.pack(pady=5)

        self.checkbutton_symbols = ttk.Checkbutton(self.root, text="Include Symbols", variable=self.include_symbols)
        self.checkbutton_symbols.pack(pady=5)

        # Generate password button
        self.btn_generate = ttk.Button(self.root, text="Generate Password", command=self.generate_password)
        self.btn_generate.pack(pady=20)

        # Password display label
        self.label_password = ttk.Label(self.root, text="")
        self.label_password.pack()

        # Copy to clipboard button
        self.btn_copy = ttk.Button(self.root, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.btn_copy.pack(pady=10)

    def generate_password(self):
        length = self.entry_length.get()

        try:
            length = int(length)
            if length <= 0:
                messagebox.showerror("Error", "Password length must be greater than zero.")
                return
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for password length.")
            return

        # Determine character set based on user selections
        characters = ''
        if self.include_letters.get():
            characters += string.ascii_letters
        if self.include_numbers.get():
            characters += string.digits
        if self.include_symbols.get():
            characters += string.punctuation

        if not characters:
            messagebox.showerror("Error", "Please select at least one option for character set.")
            return

        # Generate password
        password = ''.join(random.choice(characters) for _ in range(length))
        self.label_password.config(text=f"Generated Password: {password}")

    def copy_to_clipboard(self):
        password = self.label_password.cget("text").split(": ")[-1]
        pyperclip.copy(password)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

def main():
    root = tk.Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()