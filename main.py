import tkinter as tk
from tkinter import messagebox

class ChatLogin():
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Login")
        self.root.geometry("500x250")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")

        # Welcome label
        tk.Label(
            self.root,
            text="Welcome to Secure Chat",
            font=("Arial", 16, "bold"),
            bg="#f0f0f0"
        ).pack(pady=(20, 10))

        # Mode Selection (Host/Join)
        self.modeVar = tk.StringVar(value="host")

        modeFrame = tk.Frame(self.root, bg="#f0f0f0")
        modeFrame.pack(pady=10)

        tk.Radiobutton(
            modeFrame,
            text="Host a Chat",
            variable=self.modeVar,
            value="host",
            bg="#f0f0f0",
            command=self.update_fields
        ).pack(side=tk.LEFT, padx=10)
        
        tk.Radiobutton(
            modeFrame,
            text="Join a Chat",
            variable=self.modeVar,
            value="join",
            bg="#f0f0f0",
            command=self.update_fields
        ).pack(side=tk.LEFT, padx=10)

        # Password frame
        self.passwordFrame = tk.Frame(self.root, bg="#f0f0f0")
        self.passwordFrame.pack(pady=10)

        tk.Label(
            self.passwordFrame,
            text="Password:",
            font=("Arial", 12),
            bg="#f0f0f0"
        ).pack(side=tk.LEFT)

        self.passwordEntry = tk.Entry(
            self.passwordFrame, show="*", width=25,
            font=("Arial", 12), bd=2, relief=tk.GROOVE
        )
        self.passwordEntry.pack(side=tk.LEFT, padx=5)

        # IP frame
        self.ipFrame = tk.Frame(self.root, bg="#f0f0f0")
        
        tk.Label(
            self.ipFrame,
            text="Host IP:",
            font=("Arial", 12),
            bg="#f0f0f0"
        ).pack(side=tk.LEFT)

        self.ipEnter = tk.Entry(
            self.ipFrame, width=25,
            font=("Arial", 12), bd=2, relief=tk.GROOVE
        )
        self.ipEnter.pack(side=tk.LEFT, padx=5)

        # Enter button
        self.enterButton = tk.Button(
            self.root,
            text="ENTER",
            bg="white",
            fg="green",
            font=("Arial", 12, "bold"),
            width=10
        )
        self.enterButton.pack(side=tk.BOTTOM, pady=20)


        # Initialize fields based on default mode
        self.update_fields()

    def update_fields(self):
        # Show/hide the IP field based on selected mode
        if self.modeVar.get() == "join":
            self.ipFrame.pack(pady=5)
            #self.enterButton.pack(side=tk.BOTTOM, pady=20)
        else:
            self.ipFrame.pack_forget()
            #self.enterButton.pack_forget()

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatLogin(root)
    root.mainloop()