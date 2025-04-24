import tkinter as tk
from tkinter import messagebox, scrolledtext

class ChatLogin():
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Login")
        self.root.geometry("500x300")
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

        # Port frame
        self.portFrame = tk.Frame(self.root, bg="#f0f0f0")
        self.portFrame.pack(pady=10)

        tk.Label(
            self.portFrame,
            text="Port:",
            font=("Arial", 12),
            bg="#f0f0f0"
        ).pack(side=tk.LEFT)

        self.portEntry = tk.Entry(
            self.portFrame, width=25,
            font=("Arial", 12), bd=2, relief=tk.GROOVE
        )
        self.portEntry.pack(side=tk.LEFT, padx=5)

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
        self.enterButton.config(command=self.start_chat)


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
    
    def start_chat(self):
        """Validate inputs and start chat room"""
        # Validate inputs
        password = self.passwordEntry.get()
        if not password:
            messagebox.showerror("Error", "Password is required!")
            return
            
        if self.modeVar.get() == "join":
            ip_address = self.ipEnter.get()
            if not ip_address:
                messagebox.showerror("Error", "IP address is required to join a chat!")
                return

        # Close login window
        self.root.destroy()
        
        # Start chat room
        chat_root = tk.Tk()
        chatRoom(chat_root)  # Create chat room instance
        chat_root.mainloop()

class chatRoom():
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Room")
        self.root.geometry("600x400")
        # Background color
        self.root.configure(bg="#f0f0f0")

        self.messages = []

        # Chat display
        self.chatDisplay = scrolledtext.ScrolledText(
            self.root,
            state='disabled',
            width=60,
            height=20,
            font=("Arial", 10)
        )
        self.chatDisplay.pack(pady=10)

        # Message input frame
        inputFrame = tk.Frame(self.root)
        inputFrame.pack(pady=5, fill=tk.X, padx=10)

        self.messageEntry = tk.Entry(
            inputFrame,
            width=50,
            font=("Arial", 12)
        )
        self.messageEntry.pack(side=tk.LEFT, expand=True)
        self.messageEntry.bind("<Return>", self.sendMessage)

        sendButton = tk.Button(
            inputFrame,
            text="Send",
            command=self.sendMessage,
            width=10
        )
        sendButton.pack(side=tk.RIGHT)

    # Takes message from messageEntry and transers it to displayMessage
    def sendMessage(self, event=None):
        message = self.messageEntry.get()
        if message:
            self.displayMessage("You", message)
            self.messageEntry.delete(0, tk.END)

    # Displays message to the chatroom
    def displayMessage(self, sender, message):
        self.chatDisplay.configure(state='normal')
        self.chatDisplay.insert(tk.END, f"{sender}: {message}\n")
        self.chatDisplay.configure(state='disabled')
        self.chatDisplay.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = ChatLogin(root)
    root.mainloop()