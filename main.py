import tkinter as tk
from tkinter import messagebox

class chatLogin():
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Login")
        self.root.geometry("500x300")
        self.root.resizable(False, False)
        # Background color
        self.root.configure(bg="#f0f0f0")

        # Welcome label
        tk.Label(
            self.root,
            text="Welcome to Secure Chat",
            font=("Arial", 16, "bold"),
            bg="#f0f0f0"
        ).pack(pady=(40, 20))

        # Password Prompt label
        tk.Label(
            self.root,
            text="Enter Shared Password to Join a Private Chat",
            font=("Arial", 12),
            bg="#f0f0f0"
        ).pack(pady=(50, 20))

        # Password entry
        self.passwordEntry = tk.Entry(
            self.root, show="*", width=30,
            font=("Arial", 12), bd=2, relief=tk.GROOVE
        )
        self.passwordEntry.pack(pady=5)

        enterButton = tk.Button(
            text = "ENTER",
            bg = "white",
            fg = "green",
            font=("Arial", 12, "bold"),
            width=6
        )
        enterButton.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = chatLogin(root)
    root.mainloop()