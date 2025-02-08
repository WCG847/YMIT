import json

from tkinter import filedialog, messagebox
from WAZA.Parser import WazaParser

def open_file(self):
    try:
        filename = filedialog.askopenfilename(
            title="Open WAZA",
            filetypes=(("Yuke's Move Table Format", "*.dat"), ("All files", "*.*")),
        )
        if filename:
            # Clear the treeview before populating
            self.clear_treeview()

            parsed_data = WazaParser.parse_waza(filename)
            self.populate_treeview(json.loads(parsed_data))
    except Exception as e:
        messagebox.showerror("Error", str(e))