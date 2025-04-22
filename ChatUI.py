import tkinter as tk
from tkinter import simpledialog, scrolledtext
from AES import aes_encrypt, aes_decrypt  

class chatRoom():
    def __init__(self, root, password):
        self.root = root
        self.password = password
        self.root.title("Secure Chat Room")
        self.root.geometry("600x400")
        self.root.configure(bg="#f0f0f0")

        self.chatDisplay = scrolledtext.ScrolledText(
            self.root,
            state='disabled',
            width=60,
            height=20,
            font=("Arial", 10)
        )
        self.chatDisplay.pack(pady=10)

        inputFrame = tk.Frame(self.root)
        inputFrame.pack(pady=5, fill=tk.X, padx=10)

        self.messageEntry = tk.Entry(
            inputFrame,
            width=50,
            font=("Arial", 12)
        )
        self.messageEntry.pack(side=tk.LEFT, expand=True)

        sendButton = tk.Button(
            inputFrame,
            text="Send",
            command=self.sendMessage,
            width=10
        )
        sendButton.pack(side=tk.RIGHT)

    def sendMessage(self):
        message = self.messageEntry.get()
        if message:
            encrypted = aes_encrypt(message, self.password)
            self.displayMessage("You", encrypted, encrypted=True)
            self.messageEntry.delete(0, tk.END)

    def displayMessage(self, sender, message, encrypted=False):
        self.chatDisplay.configure(state='normal')
        if encrypted:
            decrypted = aes_decrypt(message, self.password)
            self.chatDisplay.insert(tk.END, f"{sender} (decrypted): {decrypted}\n")
        else:
            self.chatDisplay.insert(tk.END, f"{sender}: {message}\n")
        self.chatDisplay.configure(state='disabled')
        self.chatDisplay.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    password = simpledialog.askstring("Password", "Enter shared password for encryption:", show='*', parent=root)
    if not password:
        root.destroy()
    else:
        chat_ui = chatRoom(root, password)
        root.mainloop()