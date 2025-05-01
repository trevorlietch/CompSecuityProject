#UI
import tkinter as tk
from tkinter import ttk
import os
from PIL import Image, ImageTk
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

        # Canvas & Background
        self.canvas = tk.Canvas(root, width=500, height=300, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)

        try:
            here = os.path.dirname(__file__)
            bg_path = os.path.join(here, "bg_login.png")
            pil_img = Image.open(bg_path).resize((500, 300))
            self.bg = ImageTk.PhotoImage(pil_img)
            self.canvas.create_image(0, 0, image=self.bg, anchor="nw")
        except Exception as e:
                print("Could not load background:", e)

        # Welcome label
        self.canvas.create_text(
            250, 30,
            text="Welcome to Secure Chat",
            fill="white",
            font=("Arial", 14, "bold")
        )

        # Mode Selection (Host/Join)
        self.modeVar = tk.StringVar(value="host")
        self._mode_circles = {} # calls to _draw_mode() 

        # Draw the buttons with text
        def _draw_mode(x, y, mode, label):
            r = 8
            # fill white if selected, transparent otherwise
            fill = "white" if self.modeVar.get() == mode else ""
            circle = self.canvas.create_oval(x-r, y-r, x+r, y+r, outline="white", fill=fill)
            text = self.canvas.create_text(x + r + 4, y, text=label, fill="white", font=("Arial", 10), anchor="w")
            self._mode_circles[mode] = (circle, text)

        # Call for Host/Join
        _draw_mode(180, 55, "host", "Host a Chat")
        _draw_mode(310, 55, "join", "Join a Chat")

        # Catch any click on the canvas to select mode
        def _on_canvas_click(event):
            clicked_mode = None

            for mode, (circ_id, txt_id) in self._mode_circles.items():
                # test circle click
                coords = self.canvas.coords(circ_id)
                if len(coords) == 4:
                    x1,y1,x2,y2 = coords
                    cx,cy=(x1+x2)/2, (y1+y2)/2
                    r = (x2-x1)/2
                    if (event.x-cx)**2 + (event.y-cy)**2 <= r**2:
                        clicked_mode = mode

                # test text click if user doesn't click circle
                if not clicked_mode:
                    bbox= self.canvas.bbox(txt_id) # [x1,y1,x2,y2]
                    if bbox and bbox[0] <= event.x <= bbox[2] and bbox[1] <= event.y <= bbox[3]:
                        clicked_mode = mode
                
                if clicked_mode:
                    break
            
            if clicked_mode:
                # set the mode, refill circles, and update fields
                self.modeVar.set(clicked_mode)
                for m, (c_id, _) in self._mode_circles.items():
                    self.canvas.itemconfig(c_id, fill="white" if m == clicked_mode else "")
                self.update_fields()     
        self.canvas.bind("<Button-1>", self._on_canvas_click)


        # Helper to draw entries in a row
        def make_row(label, y):
            # draw the text and capture its item ID
            lbl_id = self.canvas.create_text(
                150, y,
                text=label,
                fill="white",
                font=("Arial", 10),
                anchor="e"
            )
            # create the entry and capture its window-item ID
            entry = tk.Entry(
                root,
                bg="white", fg="black",
                relief="flat", highlightthickness=1,
                highlightbackground="white",
                font=("Arial",10)
            )
            win_id = self.canvas.create_window(
                300, y, window=entry,
                width=200, height=26
            )
            return lbl_id, win_id, entry

        self.name_lbl, self.name_win, self.nameEntry = make_row("Name:", 100)
        self.name_lbl, self.password_win, self.passwordEntry = make_row("Password:", 140)
        self.port_lbl, self.port_win, self.portEntry = make_row("Port:", 180)
        self.ip_lbl, self.ip_win, self.ipEntry = make_row("IP:", 220)
        # Hide IP entry field unless "Join Chat" is selected
        self.canvas.itemconfigure(self.ip_lbl, state="hidden")
        self.canvas.itemconfigure(self.ip_win, state="hidden")

        # Enter button 
        enter_btn = tk.Button(
            root,
            text="ENTER",
            bg="white", fg="green",
            relief="flat", 
            #activebackground="#3e8e41",
            #activeforeground="white",
            font=("Arial", 10, "bold"),
            command=self.start_chat
        )
        self.canvas.create_window(250, 265, window=enter_btn, width=100, height=30)

        # Initialize fields 
        self.update_fields()
    
    def update_fields(self):
        if self.modeVar.get() == "join":
            self.canvas.itemconfigure(self.ip_lbl, state="normal")
            self.canvas.itemconfigure(self.ip_win, state="normal")
        else:
            self.canvas.itemconfigure(self.ip_lbl, state="hidden")
            self.canvas.itemconfigure(self.ip_win, state="hidden")

    def _on_canvas_click(self, event):
        # check each circle button's center and radius
        for mode, (circ,text) in self._mode_circles.items():
            # check circle hit
            x1, y1, x2, y2 = self.canvas.coords(circ)
            cx = (x1 + x2)/2
            cy = (y1 + y2)/2
            r  = (x2 - x1)/2
            inside_circle = (event.x-cx)**2 + (event.y-cy)**2 <= r**2

            # check text box hit
            tx1, ty1, tx2, ty2 = self.canvas.bbox(text)
            inside_text = (tx1 <= event.x <= tx2) and (ty1 <= event.y <= ty2)

            if inside_circle or inside_text:
                # user clicked inside this circle button
                self.modeVar.set(mode)
                # update fill of circles
                for m, (c, _) in self._mode_circles.items():
                    self.canvas.itemconfig(c, fill="white" if m==mode else "")
                # show/hide IP 
                self.update_fields()
                break
            
    def start_chat(self):
        name = self.nameEntry.get().strip()
        password = self.passwordEntry.get().strip()
        port = self.portEntry.get().strip()
        mode = self.modeVar.get()

        if not name:
            messagebox.showerror("Error", "Please enter your name.")
            return
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return
        if not port:
            messagebox.showerror("Error", "Please enter a port number.")
            return
        if mode == "join":
            ip = self.ipEntry.get().strip()
            if not ip:
                messagebox.showerror("Error", "Please enter the host IP address.")
                return
        else:
            ip = "" # or local host

        # Close login window
        self.root.destroy()

        peer = Peer(
            host=ip,
            port=port,
            password=password,
            is_server=(mode == "host"),
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
            if self.peer.crypto: #if crypto class exists then we are safe to begin sending messages
                asyncio.run_coroutine_threadsafe(
                    self.peer.send(message, "message"),
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
