import tkinter as tk
from tkinter import scrolledtext

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

        sendButton = tk.Button(
            inputFrame,
            text="Send",
            command=self.sendMessage,
            width=10
        )
        sendButton.pack(side=tk.RIGHT)

    # Takes message from messageEntry and transers it to displayMessage
    def sendMessage(self):
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
    chat_ui = chatRoom(root)
    root.mainloop()