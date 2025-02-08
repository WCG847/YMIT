import json
import struct

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, Menu
from tkinter import font as tkfont
from WAZA.Parser import WazaParser
from Manipulator import open_file
from WAZA.Deserialiser import *
from WAZA.Serialiser import *


class YMIT:
    def __init__(self, root):
        self.root = root
        self.root.title("Yuke's Move Index Tool")

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.menu_bar = Menu(root)
        self.root.config(menu=self.menu_bar)

        file_menu = Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Open", command=lambda: open_file(app))
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)

        json_menu = Menu(self.menu_bar, tearoff=0)
        json_menu.add_command(label="Serialise", command=lambda: serialise_waza(app))
        json_menu.add_command(label="Deserialise", command=lambda: deserialise_waza(app))
        self.menu_bar.add_cascade(label="JSON", menu=json_menu)

        self.tree_frame = ttk.Frame(root)
        self.tree_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        self.treeview = ttk.Treeview(self.tree_frame, columns=("Value"))
        self.treeview.heading("#0", text="Key", anchor="w")
        self.treeview.heading("Value", text="Value", anchor="w")
        self.treeview.grid(row=0, column=0, sticky="nsew")

        self.scrollbar = ttk.Scrollbar(
            self.tree_frame, orient="vertical", command=self.treeview.yview
        )
        self.scrollbar.grid(row=0, column=1, sticky="ns")
        self.treeview.configure(yscroll=self.scrollbar.set)

        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        help_menu = tk.Menu(self.menu_bar, tearoff=0)
        self.menu_bar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(
            label="About YMIT",
            command=lambda: self.about_display(
                "About YMIT",
                "Welcome to the YMIT, a powerful and user-friendly tool designed for managing WAZA/WAZE/CATE files.",
            ),
        )
        help_menu.add_command(
            label="About WCG847",
            command=lambda: self.about_display(
                "About WCG847",
                "WCG847 is a reverse engineer, and modder. He specialises in WWE games and has taken an interest since 2016.",
            ),
        )



    def clear_treeview(self):
        # Delete all items in the treeview
        for item in self.treeview.get_children():
            self.treeview.delete(item)

    def populate_treeview(self, data, parent=""):

        for key, value in data.items():
            if isinstance(value, dict):
                # Insert node for dictionaries and recurse
                node = self.treeview.insert(parent, "end", text=key, values=("dict",))
                self.populate_treeview(value, node)
            elif isinstance(value, list):
                # Insert node for lists and recurse
                node = self.treeview.insert(parent, "end", text=key, values=("list",))
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        # If list item = Dict, recurse into it
                        child_node = self.treeview.insert(
                            node, "end", text=f"Item {i}", values=("dict",)
                        )
                        self.populate_treeview(item, child_node)
                    else:
                        # If list item = primitive, directly insert its value
                        self.treeview.insert(
                            node, "end", text=f"Item {i}", values=(item,)
                        )
            else:

                self.treeview.insert(parent, "end", text=key, values=(value,))


    def about_display(self, title, description):
        about_window = tk.Toplevel()
        about_window.title(title)
        # Grab width and height
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()

        # Set window size to 80% of screen size
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.8)

        about_window.geometry(f"{window_width}x{window_height}")

        bold_font = tkfont.Font(family="Helvetica", size=12, weight="bold")

        text_widget = tk.Text(about_window, font=bold_font, wrap=tk.WORD)
        text_widget.insert(tk.END, description)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(expand=True, fill=tk.BOTH, padx=20, pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = YMIT(root)
    root.resizable(True, True)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = int(screen_width * 0.8)
    window_height = int(screen_height * 0.8)
    root.geometry(f"{window_width}x{window_height}")
    root.mainloop()