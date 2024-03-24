import scapy.all as scapy
import tkinter as tk
from tkinter import scrolledtext
from tkinter import ttk
import threading
import sys

class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        self.root.geometry("800x600")  # Adjust the window size
        self.load_icon()
        self.setup_gui()

        self.sniffing = False
        self.sniffing_thread = None
        self.selected_interface = None

        # Populate the interface list
        self.populate_interface_list()

    def setup_gui(self):
        style = ttk.Style()

        # Interface Selection
        self.interface_label = ttk.Label(root, text="Select the interface to sniff on:")
        self.interface_label.pack(pady=10)

        self.interface_listbox = ttk.Combobox(root)
        self.interface_listbox.pack(pady=10)

        # Control Buttons
        self.button_frame = ttk.Frame(root)
        self.button_frame.pack()

        self.start_button = ttk.Button(self.button_frame, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.grid(row=0, column=0, padx=5)

        self.stop_button = ttk.Button(self.button_frame, text="Stop Sniffing", command=self.stop_sniffing)
        self.stop_button.grid(row=0, column=1, padx=5)
        self.stop_button["state"] = "disabled"

        self.exit_button = ttk.Button(root, text="Exit", command=self.exit)
        self.exit_button.pack(pady=10)

        # Log Display
        self.log_text = scrolledtext.ScrolledText(root, width=80, height=30)  # Adjust the size here
        self.log_text.pack()

        style.configure("TButton", padding=5, font=("Helvetica", 12))
        style.configure("TLabel", padding=5, font=("Helvetica", 12))
        style.configure("TCombobox", padding=5, font=("Helvetica", 12))

    def load_icon(self):
        try:
            # Replace "icon.png" with the path to your image file (JPEG or PNG)
            icon_image = tk.PhotoImage(file="/Users/bab/Desktop/MiniProject/5199176-200.png")
            self.root.iconphoto(True, icon_image)
        except Exception as e:
            print(f"Error loading the icon: {str(e)}")

    def populate_interface_list(self):
        interfaces = scapy.get_if_list()
        if interfaces:
            self.selected_interface = interfaces[0]
            self.interface_listbox["values"] = interfaces
            self.interface_listbox.set(self.selected_interface)

    def start_sniffing(self):
        if not self.sniffing:
            self.selected_interface = self.interface_listbox.get()
            if self.selected_interface:
                self.sniffing = True
                self.start_button["state"] = "disabled"
                self.stop_button["state"] = "active"
                self.log(f"Sniffing on interface {self.selected_interface}...")

                self.sniffing_thread = threading.Thread(target=self.sniff_packets)
                self.sniffing_thread.start()
            else:
                self.log("Please select an interface.")

    def stop_sniffing(self):
        if self.sniffing:
            self.sniffing = False
            self.start_button["state"] = "active"
            self.stop_button["state"] = "disabled"
            self.log("Sniffing stopped.")

    def sniff_packets(self):
        try:
            scapy.conf.iface = self.selected_interface
            scapy.promisc_on()
        except Exception as e:
            self.log(f"Error: {str(e)}")
            self.log("Continuing without promiscuous mode...")

        while self.sniffing:
            packet = scapy.sniff(iface=self.selected_interface, count=1, timeout=1, store=True)
            if packet:
                self.process_packet(packet[0])

    def process_packet(self, packet):
        self.log(packet.summary())

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def exit(self):
        if self.sniffing:
            self.stop_sniffing()
        self.root.quit()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    root.mainloop()
