#UI
import tkinter as tk
from tkinter import messagebox, scrolledtext

#NETWORKING
import threading 
import asyncio
from network import Peer

#CRYPTO
from aes import Crypto


class ChatLogin():
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Login")
        self.root.geometry("500x300")
        self.root.resizable(False, False)
        self.root.configure(bg="#f0f0f0")

        # login Variables
        #self.modeVar = None

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
        self.ipFrame.pack(pady=10)

        tk.Label(
            self.ipFrame,
            text="IP:",
            font=("Arial", 12),
            bg="#f0f0f0"
        ).pack(side=tk.LEFT)

        self.ipEntry = tk.Entry(
            self.ipFrame, width=25,
            font=("Arial", 12), bd=2, relief=tk.GROOVE
        )
        self.ipEntry.pack(side=tk.LEFT, padx=5)

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
            
    def start_chat(self):
        # Store values from input fields

        if(self.modeVar.get() == "host"):
            is_server = True 
        else: is_server = False

        password = self.passwordEntry.get()
        ip = self.ipEntry.get()
        port = self.portEntry.get()

        # Validate inputs
        if not password:
            # messagebox.showerror("Error", "Password is required!")
            # return

            password = "1234"
            
        if not ip:
            # messagebox.showerror("Error", "IP address is required!")
            # return

            ip = "127.0.0.1"
        
        if not port:
            # messagebox.showerror("Error", "Port is required!")
            # return

            port = "25565"

        # Close login window
        self.root.destroy()

        peer = Peer(
            host=ip,
            port=port,
            password=password,
            is_server=is_server,
            name="Penis mucher 5000" #TREVOR name variable here
        )

        # Start chat room
        chat_root = tk.Tk()
        chatRoom(chat_root, peer)  # Create chat room instance
        chat_root.mainloop() #move into chat main loop

class chatRoom():
    def __init__(self, root, peer):
        self.root = root
        self.root.title("Secure Chat Room")
        self.root.geometry("600x400")
        # Background color
        self.root.configure(bg="#f0f0f0")

        #network

        self.peer = peer 
        self.peer.on_message = self.handleIncomingMessage

        self.messages = []

        peerThread = threading.Thread(target=self.peer.run, daemon=True)
        peerThread.start()

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

    def handleIncomingMessage(self, sender, message):
        self.root.after(0, self.displayMessage, sender, message)
    # Takes message from messageEntry and transers it to displayMessage
    def sendMessage(self, event=None):
        message = self.messageEntry.get()
        if message:
            self.displayMessage("[You] " + self.peer.name, message)

            # Send to peer over the network
            if self.peer.writer and self.peer.loop:
                asyncio.run_coroutine_threadsafe(
                    self.peer.send(message),
                    self.peer.loop
                )

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