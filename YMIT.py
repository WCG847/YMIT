import ctypes
import datetime
import json
import logging
import os
import psutil
import shlex
import struct
import subprocess
import sys
import traceback
import threading
import time


import win32con
import win32process

import tkinter as tk
from tkinter import filedialog, messagebox, ttk, Menu
from tkinter import font as tkfont

log_dir = os.path.join(os.getenv("LOCALAPPDATA"), "WCG847", "YMIT", "logs")
try:
    os.makedirs(log_dir, exist_ok=True)
except Exception as e:
    logging.error(f"Error creating log directory: {e}")
    exit(1)

log_file = os.path.join(log_dir, "log.txt")
logging.basicConfig(
    filename=log_file,
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

logging.info("Application started.")

# Define Windows priority classes
PRIORITY_CLASSES = {
    "IDLE": win32process.IDLE_PRIORITY_CLASS,
    "BELOW_NORMAL": win32process.BELOW_NORMAL_PRIORITY_CLASS,
    "NORMAL": win32process.NORMAL_PRIORITY_CLASS,
    "ABOVE_NORMAL": win32process.ABOVE_NORMAL_PRIORITY_CLASS,
    "HIGH": win32process.HIGH_PRIORITY_CLASS,
    "REALTIME": win32process.REALTIME_PRIORITY_CLASS,
}


def set_process_priority(priority_class):
    """Set the current process's priority."""
    try:
        p = psutil.Process()
        handle = ctypes.windll.kernel32.OpenProcess(
            win32con.PROCESS_ALL_ACCESS, False, p.pid
        )
        win32process.SetPriorityClass(handle, PRIORITY_CLASSES[priority_class])
        ctypes.windll.kernel32.CloseHandle(handle)
        logging.info(f"Process priority set to {priority_class}")
    except Exception as e:
        logging.error(f"Failed to set process priority: {e}")


# Constants for minidump creation
MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpWithUnloadedModules = 0x00000010
MiniDumpWithIndirectlyReferencedMemory = 0x00000020
MiniDumpFilterModulePaths = 0x00000040
MiniDumpWithProcessThreadData = 0x00000080
MiniDumpWithPrivateReadWriteMemory = 0x00000100
MiniDumpWithoutOptionalData = 0x00000200
MiniDumpWithFullMemoryInfo = 0x00000400
MiniDumpWithThreadInfo = 0x00000800
MiniDumpWithCodeSegs = 0x00001000

# Load dbghelp.dll (which contains MiniDumpWriteDump)
dbghelp = ctypes.windll.dbghelp


# Exception and Context structures (for generating a minidump)
class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [("ExceptionRecord", ctypes.c_ulong), ("ContextRecord", ctypes.c_ulong)]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", ctypes.c_ulong),
        ("Dr0", ctypes.c_ulong),
        ("Dr1", ctypes.c_ulong),
        ("Dr2", ctypes.c_ulong),
        ("Dr3", ctypes.c_ulong),
        ("Dr6", ctypes.c_ulong),
        ("Dr7", ctypes.c_ulong),
        ("FloatSave", ctypes.c_byte * 512),
        ("SegGs", ctypes.c_ulong),
        ("SegFs", ctypes.c_ulong),
        ("SegEs", ctypes.c_ulong),
        ("SegDs", ctypes.c_ulong),
        ("Edi", ctypes.c_ulong),
        ("Esi", ctypes.c_ulong),
        ("Ebx", ctypes.c_ulong),
        ("Edx", ctypes.c_ulong),
        ("Ecx", ctypes.c_ulong),
        ("Eax", ctypes.c_ulong),
        ("Ebp", ctypes.c_ulong),
        ("Eip", ctypes.c_ulong),
        ("SegCs", ctypes.c_ulong),
        ("EFlags", ctypes.c_ulong),
        ("Esp", ctypes.c_ulong),
        ("SegSs", ctypes.c_ulong),
        ("ExtendedRegisters", ctypes.c_byte * 512),
    ]


# Function to write minidump
def write_minidump(exception_type, exception_value, tb):
    dump_dir = os.path.join(os.getenv("LOCALAPPDATA"), "CrashDumps")
    os.makedirs(dump_dir, exist_ok=True)

    # Generate the dump file path with a unique timestamp and process ID
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dump_file = os.path.join(dump_dir, f"AFSUtility.{timestamp}.dmp")

    # Log the exception details
    logging.error("Uncaught exception: %s", exception_value)
    logging.error(
        "Stack trace:\n%s",
        "".join(traceback.format_exception(exception_type, exception_value, tb)),
    )

    # Set up the EXCEPTION_POINTERS and CONTEXT structures
    exception_info = EXCEPTION_POINTERS()
    context_info = CONTEXT()

    try:
        # Open the dump file for writing
        with open(dump_file, "wb") as dump_file_handle:
            # Call MiniDumpWriteDump to generate the minidump
            result = dbghelp.MiniDumpWriteDump(
                ctypes.windll.kernel32.GetCurrentProcess(),
                os.getpid(),
                dump_file_handle.fileno(),
                MiniDumpWithDataSegs
                | MiniDumpWithFullMemory
                | MiniDumpWithProcessThreadData,
                ctypes.byref(exception_info),
                ctypes.byref(context_info),
                None,
            )

            # Check if the dump was written successfully
            if result == 0:
                logging.error(
                    f"Failed to create minidump. Error code: {ctypes.windll.kernel32.GetLastError()}"
                )
            else:
                logging.info(f"Minidump successfully created at: {dump_file}")
    except Exception as e:
        logging.error(f"Failed to write crash dump: {e}")
        logging.error("Error while creating minidump.")


# Install the custom exception handler
def install_exception_handler():
    sys.excepthook = write_minidump

def restart_application():
    """Restarts the application using subprocess for automated recovery."""
    try:
        logging.info("Restarting application...")
        safe_args = [shlex.quote(arg) for arg in sys.argv]
        subprocess.Popen([sys.executable] + safe_args)
        sys.exit(0)  # Close the current instance after starting a new one
    except Exception as e:
        logging.error(f"Failed to restart application: {e}")
        messagebox.showerror(
            "Restart Failed",
            "Could not restart the application. Please restart manually.",
        )


def handle_critical_error(error):
    """Handle critical error and restart if needed."""
    logging.critical(f"Critical error encountered: {error}")
    response = messagebox.askyesno(
        "Critical Error",
        "The application encountered a critical error.\nWould you like to restart?",
    )
    if response:
        restart_application()
    else:
        sys.exit(1)


def sanitise_move_name(raw_name):
    """
    Sanitises the move name by:
    - Trimming at the first occurrence of 0x00 (null terminator).
    - Removing trailing spaces added as padding.
    """
    if raw_name:
        return raw_name.split("\x00", 1)[0].strip()
    return ""


class SVR05:
    @staticmethod
    def parse_waza(filename):
        """
        Parses Yuke's Format
        -
        """
        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        parsed_data = {"header": None, "total_moves": 0, "categories": {}, "moves": []}

        category_names = [
            "fighting_stances",
            "taunts",
            "unknown_2",
            "unknown_3",
            "unknown_4",
            "unknown_5",
            "unknown_6",
            "unknown_7",
            "unknown_8",
            "unknown_9",
            "unknown_10",
            "unknown_11",
            "unknown_12",
            "unknown_13",
            "unknown_14",
            "unknown_15",
            "unknown_16",
            "unknown_17",
            "unknown_18",
            "unknown_19",
            "unknown_20",
            "unknown_21",
            "unknown_22",
            "unknown_23",
            "unknown_24",
            "unknown_25",
            "unknown_26",
            "unknown_27",
            "unknown_28",
            "unknown_29",
            "unknown_30",
            "unknown_31",
            "unknown_32",
            "unknown_33",
            "unknown_34",
            "unknown_35",
            "unknown_36",
            "unknown_37",
            "unknown_38",
            "unknown_39",
            "unknown_40",
            "unknown_41",
            "unknown_42",
            "unknown_43",
            "unknown_44",
            "unknown_45",
            "unknown_46",
            "unknown_47",
            "unknown_48",
            "unknown_49",
            "unknown_50",
            "unknown_51",
            "unknown_52",
            "unknown_53",
            "unknown_54",
            "unknown_55",
            "unknown_56",
            "unknown_57",
            "unknown_58",
            "unknown_59",
            "unknown_60",
            "unknown_61",
            "unknown_62",
            "unknown_63",
        ]

        try:
            with open(filename, "rb") as file:

                raw_bytes = file.read(2)
                if raw_bytes == b"\xFF\x00":
                    magic_header = 0xFF00
                else:
                    magic_header = struct.unpack("<H", raw_bytes)[0]

                if magic_header != 0xFF00:
                    raise ValueError("Illegal Format: Invalid Magic")
                    logging.error("Illegal Magic Header")

                parsed_data["header"] = "SVR05"

                # Skip padding
                file.read(2)

                # Total Move Count
                total_moves = struct.unpack("<H", file.read(2))[0]
                parsed_data["total_moves"] = total_moves

                # Yet another padding to skip...
                file.read(2)

                # Read category table sector
                categories = {}
                for i in range(64):  # There are 64 Categories.
                    category_value = struct.unpack("<H", file.read(2))[0]
                    if category_value == 0xFFFF:  # EOCM (End of Category Marker)
                        break
                    elif i < len(category_names):
                        categories[category_names[i]] = category_value

                parsed_data["categories"] = categories

                # Skip EOCM
                file.read(2)
                # Read move table sector
                for move_index in range(total_moves):
                    move_index_block = {}

                    header = file.read(6)
                    if (
                        header != b"\xFF\xFF\xFF\xFF\xFF\xFF"
                    ):  # Not sure if its a header or unused flag, but it's never not 0xFF
                        raise ValueError(f"Invalid move header. Got {header}")
                    # Category flags (UINT8, 0x10 long, split into 64 bits)
                    category_flags = struct.unpack("<16B", file.read(16))
                    move_index_block["category_flags"] = {
                        category_names[i]: bool(category_flags[i // 8] & (1 << (i % 8)))
                        for i in range(64)
                        if bool(
                            category_flags[i // 8]
                            & (1 << (i % 8))  # Only display categories set to True
                        )
                    }

                    move_name = file.read(32).decode("utf-8")
                    move_index_block["name"] = sanitise_move_name(move_name)

                    damage_flags = struct.unpack("<3B", file.read(3))
                    move_index_block["damage_flags"] = {
                        "unknown_flag": damage_flags[0],
                        "damage_value": damage_flags[1],
                        "exclusive_id": damage_flags[  # Which wrestler the move depends on.
                            2
                        ],
                    }

                    # Column flag mappings
                    column_flag_map = {
                        0x01: "GY BACK",
                        0x02: "Upper Ground",
                        0x03: "Lower Ground",
                        0x04: "Ground Facing Up U",
                        0x05: "Ground Facing Up L",
                        0x06: "Face on Ground U",
                        0x07: "Face on Ground L",
                        0x08: "Down Diving",
                        0x09: "Face TB",
                        0x0A: "Back TB",
                        0x0B: "Under TB",
                        0x0C: "Rope Down",
                        0x0D: "Stand Diving",
                        0x0E: "Running",
                    }

                    # Extract parameters
                    parameters = file.read(5)
                    column_flag_byte = parameters[0]
                    column_flags = (
                        {column_flag_map[column_flag_byte]: True}
                        if column_flag_byte in column_flag_map
                        else {}
                    )
                    if not isinstance(
                        column_flags, dict
                    ):  # Ensure column_flags is a dictionary
                        column_flags = {}  # Default to an empty dictionary
                    move_index_block["column_flags"] = column_flags

                    # Exclude the first byte and extract unlock_id
                    unlock_id = parameters[1]
                    unlock_id_2 = parameters[2]
                    move_index_block["unlock_id"] = unlock_id
                    move_index_block["unlock_id_2"] = unlock_id_2
                    move_index_block["parameters"] = [
                        int(b) for b in parameters[3:]  # Remaining bytes (if any)
                    ]

                    move_index_id = struct.unpack("<H", file.read(2))[0]
                    move_index_block["id"] = int(move_index_id)  # Convert to decimal

                    parsed_data["moves"].append(move_index_block)

        except FileNotFoundError:
            raise FileNotFoundError(f"File {filename} not found.")
        except Exception as e:
            raise RuntimeError(f"An error occurred while parsing the file: {str(e)}")

        return json.dumps(parsed_data, indent=4)


class YMIT:
    def __init__(self, root):
        self.root = root
        self.root.title("Yuke's Move Index Tool")
        self.config_path = os.path.join(
            os.getenv("LOCALAPPDATA"), "WCG847", "YMIT", "config", "config.json"
        )
        self.active_threads = []
        self.lock = threading.Lock()
        # Initialise default settings
        self.settings = {
            "theme": "light",  # default theme
            "font": "Helvetica",  # default font
        }

        # Try loading settings from the config file
        self.load_settings()

        # Apply theme and font
        self.apply_theme_and_font()

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self.menu_bar = Menu(root)
        self.root.config(menu=self.menu_bar)

        file_menu = Menu(self.menu_bar, tearoff=0)
        file_menu.add_command(label="Open", command=self.open_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=root.quit)
        self.menu_bar.add_cascade(label="File", menu=file_menu)

        json_menu = Menu(self.menu_bar, tearoff=0)
        json_menu.add_command(label="Serialise", command=self.serialise_waza)
        json_menu.add_command(label="Deserialise", command=self.deserialise_waza)
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

        pref_menu = Menu(self.menu_bar, tearoff=0)
        pref_menu.add_command(label="Settings", command=self.pref_display)
        self.menu_bar.add_cascade(label="Preferences", menu=pref_menu)

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
        # Initialise last heartbeat timestamp
        self.last_heartbeat = time.time()

        # Start monitoring application health in a separate thread
        monitoring_thread = threading.Thread(target=self.watchdog, daemon=True)
        monitoring_thread.start()

    # Add calls to handle_critical_error in relevant try-except blocks
    def monitor_and_adjust_priority(self):
        try:
            p = psutil.Process()
            while True:
                cpu_usage = p.cpu_percent(interval=1)
                if cpu_usage < 10:
                    set_process_priority("IDLE")
                elif 10 <= cpu_usage < 30:
                    set_process_priority("BELOW_NORMAL")
                elif 30 <= cpu_usage < 60:
                    set_process_priority("NORMAL")
                elif 60 <= cpu_usage < 80:
                    set_process_priority("ABOVE_NORMAL")
                else:
                    set_process_priority("HIGH")
                logging.info(f"CPU usage: {cpu_usage}% - Priority adjusted.")
                time.sleep(5)
        except Exception as e:
            handle_critical_error(e)

    def update_heartbeat(self):
        """Update the heartbeat timestamp periodically, even if there is no user input."""
        self.last_heartbeat = time.time()
        logging.debug("Heartbeat updated.")

    def watchdog(self):
        """Monitor the application's health, distinguishing between lockup and inactivity."""
        max_inactive_duration = 300  # 5 minutes
        while True:
            time.sleep(10)
            time_since_last_heartbeat = time.time() - self.last_heartbeat
            if time_since_last_heartbeat > max_inactive_duration:
                logging.warning(
                    f"No heartbeat detected in {time_since_last_heartbeat} seconds. "
                    "Application may be unresponsive."
                )
                # Check for potential freeze
                self.monitor_for_freeze()
            else:
                logging.debug("Application heartbeat is active.")

    def monitor_for_freeze(self):
        """Monitor CPU usage to detect if the application is frozen."""
        try:
            p = psutil.Process()
            cpu_usage = p.cpu_percent(interval=1)
            if (
                cpu_usage < 5
            ):  # Assumes the application is frozen if CPU usage is below 5%
                logging.warning(
                    "CPU usage is extremely low, indicating potential freeze."
                )
                self.ask_for_manual_recovery()
            else:
                logging.info(
                    f"Application is responsive with CPU usage at {cpu_usage}%"
                )
        except Exception as e:
            logging.error(f"Error while checking CPU usage: {e}")

    def ask_for_manual_recovery(self):
        response = messagebox.askyesno(
            "Application Not Responding",
            "It seems the application has stopped responding. Do you want to attempt recovery?",
        )
        if response:
            self.attempt_recovery()
        else:
            logging.error("User opted not to attempt recovery. Exiting.")
            sys.exit(1)

    def is_healthy(self):
        return self.afs_path is not None and self.tree.get_children()

    def attempt_recovery(self):
        try:
            if self.afs_path:
                with open(self.afs_path, "rb") as afs_file:
                    self.parse_afs(afs_file)
                messagebox.showinfo("Recovery", "Application recovered successfully.")
        except Exception as e:
            handle_critical_error(e)

    def run_in_thread(self, target, *args, timeout=None, max_retries=1):
        """
        Runs a target function in a new thread with enhanced lifecycle management.

        Parameters:
        - target: Callable to execute in the thread.
        - args: Positional arguments for the target function.
        - timeout: Maximum allowed time for the thread to complete (in seconds). Default is None (no timeout).
        - max_retries: Maximum number of times to retry in case of failure. Default is 1.
        """

        def thread_wrapper():
            nonlocal retries
            try:
                logging.info(f"Thread started for {target.__name__} with args: {args}")
                retries = 0
                while retries <= max_retries:
                    start_time = time.time()
                    try:
                        target(*args)
                        break  # Exit loop if successful
                    except Exception as e:
                        retries += 1
                        logging.error(
                            f"Error in thread ({target.__name__}): {e}. Retrying {retries}/{max_retries}"
                        )
                        if retries > max_retries:
                            raise
                        time.sleep(2)  # Backoff before retrying

                    # Timeout enforcement
                    elapsed_time = time.time() - start_time
                    if timeout and elapsed_time > timeout:
                        logging.error(
                            f"Thread {target.__name__} timed out after {timeout} seconds."
                        )
                        raise TimeoutError(
                            f"Execution of {target.__name__} exceeded timeout."
                        )
                else:
                    logging.info(
                        f"Thread for {target.__name__} completed successfully."
                    )

            except Exception as e:
                logging.error(f"Thread {target.__name__} failed: {e}")

            finally:
                with self.lock:
                    self.active_threads.remove(thread)
                logging.info(f"Thread for {target.__name__} ended.")

        # Create and track the thread
        retries = 0
        thread = threading.Thread(
            target=thread_wrapper, daemon=True
        )  # Daemon thread to ensure it exits with the main program
        with self.lock:
            self.active_threads.append(thread)
        thread.start()
        logging.info(f"Thread {thread.name} started for target {target.__name__}.")
    def pref_display(self):
        # Create a new window for preferences
        pref_window = tk.Toplevel(self.root)
        pref_window.title("Preferences")

        # Theme selection
        theme_label = tk.Label(pref_window, text="Select Theme:")
        theme_label.grid(row=0, column=0, padx=10, pady=10)

        theme_var = tk.StringVar(value=self.settings["theme"])
        light_theme_rb = tk.Radiobutton(
            pref_window, text="Light", variable=theme_var, value="light"
        )
        dark_theme_rb = tk.Radiobutton(
            pref_window, text="Dark", variable=theme_var, value="dark"
        )

        light_theme_rb.grid(row=0, column=1, padx=10, pady=10)
        dark_theme_rb.grid(row=0, column=2, padx=10, pady=10)

        # Font selection
        font_label = tk.Label(pref_window, text="Select Font:")
        font_label.grid(row=1, column=0, padx=10, pady=10)

        font_list = list(tkfont.families())
        font_var = tk.StringVar(value=self.settings["font"])
        font_menu = ttk.Combobox(
            pref_window, textvariable=font_var, values=font_list, state="readonly"
        )
        font_menu.grid(row=1, column=1, padx=10, pady=10)

        # Save button
        save_button = tk.Button(
            pref_window,
            text="Save",
            command=lambda: self.save_preferences(
                theme_var.get(), font_var.get(), pref_window
            ),
        )
        save_button.grid(row=2, column=0, columnspan=3, pady=20)

    def save_preferences(self, theme, font, window):
        # Update settings in memory
        self.settings["theme"] = theme
        self.settings["font"] = font

        # Ensure directory for config path exists
        config_dir = os.path.dirname(self.config_path)
        try:
            if not os.path.exists(config_dir):
                os.makedirs(config_dir)
                logging.debug(f"Created directory for config at {config_dir}")
        except Exception as e:
            logging.error(f"Failed to create directory for config: {e}")
            messagebox.showerror("Error", f"Failed to create directory: {e}")
            return

        # Save settings to config.json
        try:
            with open(self.config_path, "w") as config_file:
                json.dump(self.settings, config_file, indent=4)
            logging.info(f"Settings saved to {self.config_path}")
        except Exception as e:
            logging.error(f"Failed to save settings: {e}")
            messagebox.showerror("Error", f"Failed to save settings: {e}")
            return

        # Apply changes and close preferences window
        self.apply_theme_and_font()
        window.destroy()
        messagebox.showinfo("Settings Saved", "Your preferences have been saved.")

    def apply_theme_and_font(self):
        # Apply the selected theme and font
        if self.settings["theme"] == "dark":
            self.root.configure(bg="black")
            self.root.option_add("*foreground", "white")
            self.root.option_add("*background", "black")
        else:
            self.root.configure(bg="white")
            self.root.option_add("*foreground", "black")
            self.root.option_add("*background", "white")

        # Apply selected font to the whole window
        font = (self.settings["font"], 10)
        self.root.option_add("*font", font)

    def load_settings(self):
        # Load settings from config.json if it exists
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as config_file:
                    self.settings = json.load(config_file)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load settings: {e}")

    def open_file(self):
        try:
            filename = filedialog.askopenfilename(
                title="Open WAZA",
                filetypes=(("Yuke's Move Table Format", "*.dat"), ("All files", "*.*")),
            )
            if filename:
                parsed_data = SVR05.parse_waza(filename)
                self.populate_treeview(json.loads(parsed_data))
        except Exception as e:
            messagebox.showerror("Error", str(e))

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

    def deserialise_waza(self):
        def tree_to_structure(parent=""):
            children = self.treeview.get_children(parent)

            if not children:
                values = self.treeview.item(parent, "values")
                if values and values[0]:
                    try:
                        return json.loads(values[0])
                    except json.JSONDecodeError:
                        return values[0]
                    return None

            first_child_values = self.treeview.item(children[0], "values")
            if first_child_values and first_child_values[0] == "list_item":
                return [tree_to_structure(child) for child in children]
            else:
                result = {}
                for child in children:
                    key = self.treeview.item(child, "text")
                    if key == "categories" or key == "total_moves":
                        continue
                    value = tree_to_structure(child)
                    result[key] = value
                return result

        filename = filedialog.asksaveasfilename(
            title="Save JSON File",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if filename:
            try:
                data = tree_to_structure()
                with open(filename, "w") as f:
                    json.dump(data, f, indent=4)
                messagebox.showinfo("Success", "File saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def serialise_waza(self):
        input_json_filename = filedialog.askopenfilename(
            title="Select JSON",
            filetypes=(("JSON Files", "*.json"), ("All Files", "*.*")),
        )
        if not input_json_filename:
            return

        output_waza_filename = filedialog.asksaveasfilename(
            title="Save WAZA",
            defaultextension=".dat",
            filetypes=(("Yuke's Move Table Format", "*.dat"), ("All Files", "*.*")),
        )
        if not output_waza_filename:
            return

        try:
            with open(input_json_filename, "r") as json_file:
                data = json.load(json_file)

            moves = data.get("moves", {})
            if not isinstance(moves, dict):
                raise ValueError("'moves' must be a dictionary in the JSON schema.")

            moves_list = list(moves.values())  # Extract the list of moves
            total_moves = len(moves_list)

            # Dynamically calculate category counts based on category_names
            category_names = [
                "fighting_stances",
                "taunts",
                "unknown_2",
                "unknown_3",
                "unknown_4",
                "unknown_5",
                "unknown_6",
                "unknown_7",
                "unknown_8",
                "unknown_9",
                "unknown_10",
                "unknown_11",
                "unknown_12",
                "unknown_13",
                "unknown_14",
                "unknown_15",
                "unknown_16",
                "unknown_17",
                "unknown_18",
                "unknown_19",
                "unknown_20",
                "unknown_21",
                "unknown_22",
                "unknown_23",
                "unknown_24",
                "unknown_25",
                "unknown_26",
                "unknown_27",
                "unknown_28",
                "unknown_29",
                "unknown_30",
                "unknown_31",
                "unknown_32",
                "unknown_33",
                "unknown_34",
                "unknown_35",
                "unknown_36",
                "unknown_37",
                "unknown_38",
                "unknown_39",
                "unknown_40",
                "unknown_41",
                "unknown_42",
                "unknown_43",
                "unknown_44",
                "unknown_45",
                "unknown_46",
                "unknown_47",
                "unknown_48",
                "unknown_49",
                "unknown_50",
                "unknown_51",
                "unknown_52",
                "unknown_53",
                "unknown_54",
                "unknown_55",
                "unknown_56",
                "unknown_57",
                "unknown_58",
                "unknown_59",
                "unknown_60",
                "unknown_61",
                "unknown_62",
                "unknown_63",
            ]

            category_counts = {name: 0 for name in category_names}
            for move in moves_list:
                if not isinstance(move, dict):
                    continue  # Skip invalid moves that are not dictionaries
                category_flags = move.get("category_flags", {})
                for category, is_flag_set in category_flags.items():
                    if category in category_counts and is_flag_set == "True":
                        category_counts[category] += 1

            with open(output_waza_filename, "wb") as binary_file:
                # Write header and pads
                binary_file.write(b"\xFF\x00\x00\x00")
                binary_file.write(struct.pack("<H", total_moves))
                binary_file.write(b"\x00\x00")

                # Serialise category counts in the order of category_names
                for category in category_names:
                    binary_file.write(struct.pack("<H", category_counts[category]))
                binary_file.write(struct.pack("<H", 0xFFFF))  # End of category marker

                for move in moves_list:
                    if not isinstance(move, dict):
                        continue

                    binary_file.write(b"\xFF\xFF\xFF\xFF\xFF\xFF")

                    # Handle category flags
                    category_flags = [0] * 16
                    move_category_flags = move.get("category_flags", {})
                    for category, is_flag_set in move_category_flags.items():
                        if is_flag_set == "True" and category in category_names:
                            category_index = category_names.index(category)
                            byte_index = category_index // 8
                            bit_position = category_index % 8
                            category_flags[byte_index] |= 1 << bit_position
                    binary_file.write(struct.pack("<16B", *category_flags))

                    # Handle move name
                    move_name = move.get("name", "Unknown")
                    if not isinstance(move_name, str):
                        move_name = "Unknown"
                    binary_file.write(move_name.ljust(32, "\x00").encode("utf-8"))

                    # Handle damage flags
                    damage_flags = move.get("damage_flags", {})
                    if not isinstance(damage_flags, dict):
                        damage_flags = {}
                    binary_file.write(
                        struct.pack(
                            "<3B",
                            int(damage_flags.get("unknown_flag", 0)),
                            int(damage_flags.get("damage_value", 0)),
                            int(damage_flags.get("exclusive_id", 0)),
                        )
                    )

                    # Handle column flags
                    # Column flag mappings
                    column_flag_map = {
                        0x01: "GY BACK",
                        0x02: "Upper Ground",
                        0x03: "Lower Ground",
                        0x04: "Ground Facing Up U",
                        0x05: "Ground Facing Up L",
                        0x06: "Face on Ground U",
                        0x07: "Face on Ground L",
                        0x08: "Down Diving",
                        0x09: "Face TB",
                        0x0A: "Back TB",
                        0x0B: "Under TB",
                        0x0C: "Rope Down",
                        0x0D: "Stand Diving",
                        0x0E: "Running",
                    }

                    # Ensure column_flags is a dictionary
                    column_flags = move.get("column_flags", {})
                    if isinstance(
                        column_flags, str
                    ):  # If column_flags is a string (incorrect format)
                        # Attempt to parse string into a dictionary
                        try:
                            column_flags = json.loads(column_flags)
                        except (json.JSONDecodeError, TypeError):
                            column_flags = (
                                {}
                            )  # Fallback to empty dictionary if parsing fails

                    if not isinstance(
                        column_flags, dict
                    ):  # Final check to ensure it's a dictionary
                        column_flags = {}

                    # Default column_flag_byte to 0x00 (disabled)
                    column_flag_byte = 0x00
                    for key, value in column_flags.items():
                        if value and key in column_flag_map.values():
                            # Find the corresponding byte value for the flag name
                            column_flag_byte = list(column_flag_map.keys())[
                                list(column_flag_map.values()).index(key)
                            ]
                            break

                    # Handle parameters
                    parameters = move.get(
                        "parameters", [0, 0]
                    )  # Expect 2 unknown items
                    if not isinstance(parameters, list) or len(parameters) != 2:
                        parameters = [0, 0]  # Default to 2 zeros

                    # Include unlock_id and unlock_id_flag in the parameters
                    unlock_id = move.get("unlock_id", 0)
                    unlock_id_2 = move.get("unlock_id_2", 0)
                    if not isinstance(unlock_id, int) or not (0 <= unlock_id <= 255):
                        unlock_id = 0  # Default to 0 if invalid
                    if not isinstance(unlock_id_2, int) or not (0 <= unlock_id_2 <= 255):
                        unlock_id_2 = 0  # Default to 0 if invalid

                    # Construct the final 5-byte parameters array
                    parameters_with_flags = [column_flag_byte, unlock_id, unlock_id_2, *parameters]
                    binary_file.write(struct.pack("<5B", *parameters_with_flags))


                    # Handle move ID
                    move_id = move.get("id", 0)
                    if not isinstance(move_id, int):
                        move_id = 0
                    binary_file.write(struct.pack("<H", move_id))

            messagebox.showinfo(
                "Serialisation Complete", f"Output saved to {output_waza_filename}"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))

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