import ctypes
import json
import logging
import os
import psutil
import struct
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

def monitor_and_adjust_priority(self):
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

def sanitise_move_name(raw_name):
    """
    Sanitises the move name by:
    - Trimming at the first occurrence of 0x00 (null terminator).
    - Removing trailing spaces added as padding.
    """
    if raw_name:
        return raw_name.split("\x00", 1)[0].strip()
    return ""


SVR_HCTP_CATE_NAMES = [
    "fighting_stances",
    "taunts",
    "chair_finishers",
    "standard_finishers",
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
    "strikes",
    "back_grapples",
    "upper_ground_grapples",
    "lower_ground_grapples",
    "front_cell_grapples",
    "back_cell_grapples",
    "ground_strikes",
    "unknown_22",
    "unknown_23",
    "rope_grapples",
    "front_corner_grapples",
    "back_corner_grapples",
    "running_front_corner_strikes",
    "seated_corner_grapples",
    "running_seated_corner_strikes",
    "diving_to_standing_opp",
    "diving_to_grounded_opp",
    "outside_dives",
    "rebound_attacks",
    "grounded_rebound_attacks",
    "springboard",
    "irish_whip/turn_behind",
    "running_grapples",
    "running_strikes",
    "running_ground_strikes",
    "unknown_40",
    "prim_running_back_grapples",
    "sec_running_back_grapples",
    "running_counter_grapples",
    "standing_team_grapples",
    "corner_team_grapples",
    "ring_in",
    "ring_out",
    "strike_combinations_1",
    "strike_combinations_2",
    "grapple_attacks",
    "upper_pins",
    "lower_pins",
    "unk_submission_cate",
    "unknown_54",
    "running_stance",
    "blood",
    "unknown_57",
    "walking_stance",
    "unknown_59",
    "unknown_60",
    "unknown_61",
    "unknown_62",
    "unknown_63",
]
SVR06_CATE_NAMES = [
    "fighting_stances",
    "taunts",
    "chair_finishers",
    "standard_finishers",
    "clean_grapples",
    "dirty_grapples",
    "submission_grapples",
    "power_grapples",
    "speed_grapples",
    "technique_grapples",
    "brawler_grapples",
    "martial_arts_grapples",
    "unknown_12",
    "luchador_grapples",
    "old_school_grapples",
    "strikes",
    "back_grapples",
    "upper_ground_grapples",
    "lower_ground_grapples",
    "front_cell_grapples",
    "back_cell_grapples",
    "ground_strikes",
    "unknown_22",
    "unknown_23",
    "rope_grapples",
    "front_corner_grapples",
    "back_corner_grapples",
    "running_front_corner_strikes",
    "seated_corner_grapples",
    "running_seated_corner_strikes",
    "diving_to_standing_opp",
    "diving_to_grounded_opp",
    "outside_dives",
    "rebound_attacks",
    "grounded_rebound_attacks",
    "springboard",
    "irish_whip/turn_behind",
    "running_grapples",
    "running_strikes",
    "running_ground_strikes",
    "unknown_40",
    "prim_running_back_grapples",
    "sec_running_back_grapples",
    "running_counter_grapples",
    "standing_team_grapples",
    "corner_team_grapples",
    "ring_in",
    "ring_out",
    "strike_combinations_1",
    "strike_combinations_2",
    "grapple_attacks",
    "upper_pins",
    "lower_pins",
    "unk_submission_cate",
    "unknown_54",
    "running_stance",
    "blood",
    "unknown_57",
    "walking_stance",
    "unknown_59",
    "unknown_60",
    "unknown_61",
    "unknown_62",
    "unknown_63",
]

WWE14_CATE_NAMES = [
    "unknown_0",
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
    "unknown_64",
    "unknown_65",
    "unknown_66",
    "unknown_67",
    "unknown_68",
    "unknown_69",
    "unknown_70",
    "unknown_71",
    "unknown_72",
    "unknown_73",
    "unknown_74",
    "unknown_75",
    "unknown_76",
    "unknown_77",
    "unknown_78",
    "unknown_79",
    "unknown_80",
    "unknown_81",
    "unknown_82",
    "unknown_83",
    "unknown_84",
    "unknown_85",
    "unknown_86",
    "unknown_87",
    "unknown_88",
    "unknown_89",
    "unknown_90",
    "unknown_91",
    "unknown_92",
    "unknown_93",
    "unknown_94",
    "unknown_95",
    "unknown_96",
    "unknown_97",
    "unknown_98",
    "unknown_99",
    "unknown_100",
    "unknown_101",
    "unknown_102",
    "unknown_103",
    "unknown_104",
    "unknown_105",
    "unknown_106",
    "unknown_107",
    "unknown_108",
    "unknown_109",
    "unknown_110",
    "unknown_111",
    "unknown_112",
    "unknown_113",
    "unknown_114",
    "unknown_115",
    "unknown_116",
    "unknown_117",
    "unknown_118",
    "unknown_119",
    "unknown_120",
    "unknown_121",
    "unknown_122",
    "unknown_123",
    "unknown_124",
    "unknown_125",
    "unknown_126",
    "unknown_127",
    "unknown_128",
    "unknown_129",
    "unknown_130",
    "unknown_131",
    "unknown_132",
    "unknown_133",
    "unknown_134",
    "unknown_135",
    "unknown_136",
    "unknown_137",
    "unknown_138",
    "unknown_139",
    "unknown_140",
    "unknown_141",
    "unknown_142",
    "unknown_143",
    "unknown_144",
    "unknown_145",
    "unknown_146",
    "unknown_147",
    "unknown_148",
    "unknown_149",
    "unknown_150",
    "unknown_151",
    "unknown_152",
    "unknown_153",
    "unknown_154",
    "unknown_155",
    "unknown_156",
    "unknown_157",
    "unknown_158",
    "unknown_159",
    "unknown_160",
    "unknown_161",
    "unknown_162",
]

SVR11_CATE_NAMES = [
    "unknown_0",
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
    "unknown_64",
    "unknown_65",
    "unknown_66",
    "unknown_67",
    "unknown_68",
    "unknown_69",
    "unknown_70",
    "unknown_71",
    "unknown_72",
    "unknown_73",
    "unknown_74",
    "unknown_75",
    "unknown_76",
    "unknown_77",
    "unknown_78",
    "unknown_79",
    "unknown_80",
    "unknown_81",
    "unknown_82",
    "unknown_83",
    "unknown_84",
    "unknown_85",
    "unknown_86",
    "unknown_87",
    "unknown_88",
    "unknown_89",
    "unknown_90",
    "unknown_91",
    "unknown_92",
    "unknown_93",
    "unknown_94",
    "unknown_95",
    "unknown_96",
    "unknown_97",
    "unknown_98",
    "unknown_99",
    "unknown_100",
    "unknown_101",
    "unknown_102",
    "unknown_103",
    "unknown_104",
    "unknown_105",
    "unknown_106",
    "unknown_107",
    "unknown_108",
    "unknown_109",
    "unknown_110",
    "unknown_111",
    "unknown_112",
    "unknown_113",
    "unknown_114",
    "unknown_115",
    "unknown_116",
    "unknown_117",
    "unknown_118",
    "unknown_119",
    "unknown_120",
    "unknown_121",
    "unknown_122",
    "unknown_123",
    "unknown_124",
    "unknown_125",
    "unknown_126",
    "unknown_127",
]

COLUMN_FLAG_MAP = {
    0x00: "GY FRONT",
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


class SYM:
    @staticmethod
    def parse_waza(filename):
        """
        Parses SYM Move Format
        """

        set_process_priority("ABOVE_NORMAL")

        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        parsed_data = {"header": None, "total_moves": 0, "moves": []}

        try:
            with open(filename, "rb") as file:
                # Read and validate the magic header
                file.read(2)
                total_moves = struct.unpack("<H", file.read(2))[0]
                parsed_data["total_moves"] = total_moves

                parsed_data["header"] = "SYM"

                # Skip padding
                file.read(2)

                # Start reading the move table sector directly
                for move_index in range(total_moves):
                    move_index_block = {}
                    move_index_id = struct.unpack("<H", file.read(2))[0]
                    move_index_block["id"] = int(move_index_id)  # Convert to decimal
                    file.read(1)
                    unk1 = struct.unpack("<H", file.read(2))[0]
                    move_index_block["unk1"] = int(unk1)
                    file.read(1)
                    unk2 = struct.unpack("<H", file.read(2))[0]
                    move_index_block["unk2"] = int(unk2)
                    move_name = file.read(28).decode("utf-8")
                    move_index_block["name"] = sanitise_move_name(move_name)

                    parameters = file.read(4)
                    move_index_block["parameters"] = [
                        int(b) for b in parameters[4:]  # Remaining bytes (if any)
                    ]
                    parsed_data["moves"].append(move_index_block)

        except FileNotFoundError:
            raise FileNotFoundError(f"File {filename} not found.")
        except Exception as e:
            raise RuntimeError(f"An error occurred while parsing the file: {str(e)}")

        finally:
            # After parsing, reset the process priority to NORMAL
            set_process_priority("NORMAL")

        return json.dumps(parsed_data, indent=4)


class HCTP:
    @staticmethod
    def parse_waza(filename):
        """
        Parses HCTP Move Format
        """
        category_names = SVR_HCTP_CATE_NAMES
        column_flag_map = COLUMN_FLAG_MAP

        set_process_priority("ABOVE_NORMAL")

        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        parsed_data = {"header": None, "total_moves": 0, "moves": []}

        try:
            with open(filename, "rb") as file:
                # Read and validate the magic header
                raw_bytes = file.read(2)
                if raw_bytes == b"\xFF\x00":
                    magic_header = 0xFF00
                else:
                    magic_header = struct.unpack("<H", raw_bytes)[0]

                if magic_header != 0xFF00:
                    raise ValueError("Illegal Format: Invalid Magic")
                    logging.error("Illegal Magic Header")

                parsed_data["header"] = "HCTP"

                # Skip padding
                file.read(2)

                # Total Move Count
                total_moves = struct.unpack("<H", file.read(2))[0]
                parsed_data["total_moves"] = total_moves

                # Skip the next padding bytes
                file.read(10)

                # Start reading the move table sector directly
                for move_index in range(total_moves):
                    move_index_block = {}

                    if move_index == 0:
                        # First move has no header, starts directly with category flags
                        category_flags = struct.unpack("<16B", file.read(16))
                    else:
                        # Subsequent moves have a header
                        header = file.read(6)
                        if header != b"\xFF\xFF\xFF\xFF\xFF\xFF":
                            raise ValueError(
                                f"Invalid move header at index {move_index}"
                            )
                        category_flags = struct.unpack("<16B", file.read(16))

                    # Category flags (UINT8, 0x10 long, split into 64 bits)
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

        finally:
            # After parsing, reset the process priority to NORMAL
            set_process_priority("NORMAL")

        return json.dumps(parsed_data, indent=4)


class SVR05:
    @staticmethod
    def parse_waza(filename):
        """
        Parses Yuke's Format
        -
        """
        category_names = SVR_HCTP_CATE_NAMES
        column_flag_map = COLUMN_FLAG_MAP
        set_process_priority("ABOVE_NORMAL")

        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        parsed_data = {"header": None, "total_moves": 0, "categories": {}, "moves": []}

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

        finally:
            # After parsing, reset the process priority to NORMAL
            set_process_priority("NORMAL")

        return json.dumps(parsed_data, indent=4)


class SVR06:
    @staticmethod
    def parse_waza(filename):
        """
        Parses Yuke's Format
        -
        """
        category_names = SVR06_CATE_NAMES
        column_flag_map = COLUMN_FLAG_MAP
        set_process_priority("ABOVE_NORMAL")

        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        parsed_data = {"header": None, "total_moves": 0, "categories": {}, "moves": []}

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

                parsed_data["header"] = "SVR06"

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

                    move_name = file.read(96).decode("utf-8")
                    move_index_block["name"] = sanitise_move_name(move_name)

                    damage_flags = struct.unpack("<3B", file.read(3))
                    move_index_block["damage_flags"] = {
                        "unknown_flag": damage_flags[0],
                        "damage_value": damage_flags[1],
                        "exclusive_id": damage_flags[  # Which wrestler the move depends on.
                            2
                        ],
                    }

                    # Extract parameters
                    parameters = file.read(21)
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
                    unlock_id = parameters[11]
                    unlock_id_2 = parameters[12]
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

        finally:
            # After parsing, reset the process priority to NORMAL
            set_process_priority("NORMAL")

        return json.dumps(parsed_data, indent=4)

class SVR11:
    @staticmethod
    def parse_waza(filename):
        """
        Parses Yuke's Format
        -
        """
        category_names = SVR11_CATE_NAMES
        column_flag_map = COLUMN_FLAG_MAP
        set_process_priority("ABOVE_NORMAL")

        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        parsed_data = {"header": None, "total_moves": 0, "categories": {}, "moves": []}

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

                parsed_data["header"] = "SVR11"

                # Skip padding
                file.read(2)

                # Total Move Count
                total_moves = struct.unpack("<H", file.read(2))[0]
                parsed_data["total_moves"] = total_moves

                # Yet another padding to skip...
                file.read(2)

                # Read category table sector
                categories = {}
                for i in range(128):  # There are 128 Categories.
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
                    # Category flags (UINT8, 0x10 long, split into 128 bits)
                    category_flags = struct.unpack("<16B", file.read(16))
                    move_index_block["category_flags"] = {
                        category_names[i]: bool(category_flags[i // 8] & (1 << (i % 8)))
                        for i in range(128)
                        if bool(
                            category_flags[i // 8]
                            & (1 << (i % 8))  # Only display categories set to True
                        )
                    }

                    move_name = file.read(96).decode("utf-8")
                    move_index_block["name"] = sanitise_move_name(move_name)

                    damage_flags = struct.unpack("<10B", file.read(10))
                    move_index_block["damage_flags"] = {
                        "unk1": damage_flags[0],
                        "unk2": damage_flags[1],
                        "unk3": damage_flags[2],
                        "unk4": damage_flags[3],
                        "unk5": damage_flags[4],
                        "unk6": damage_flags[5],
                        "unk7": damage_flags[6],
                        "unk8": damage_flags[7],
                        "unk9": damage_flags[8],
                        "exclusive_id": damage_flags[9]
                    }


                    # Extract parameters
                    parameters = file.read(21)
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
                    unlock_id = parameters[11]
                    unlock_id_2 = parameters[12]
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

        finally:
            # After parsing, reset the process priority to NORMAL
            set_process_priority("NORMAL")

        return json.dumps(parsed_data, indent=4)


class WazaParser:
    @staticmethod
    def parse_waza(filename):
        """
        Determines the format of the WAZA file and parses it accordingly.
        """
        set_process_priority("ABOVE_NORMAL")

        if not filename.endswith(".dat"):
            raise ValueError("File must be of type '.DAT'")

        try:
            with open(filename, "rb") as file:
                # Validate magic header
                raw_bytes = file.read(2)
                if raw_bytes == b"\xFF\x00":
                    magic_header = 0xFF00
                else:
                    magic_header = struct.unpack("<H", raw_bytes)[0]

                if magic_header != 0xFF00:
                    raise ValueError("Illegal Format: Invalid Magic")
                    logging.error("Illegal Magic Header")

                # Check for specific formats based on offsets
                # Check offset 0xC0 for SVR05 or SVR06
                file.seek(0xC0)
                offset_c0_bytes = file.read(3)
                if offset_c0_bytes == b"\x03\x0A\xFF":
                    logging.info("Detected SVR05 WAZA format.")
                    return SVR05.parse_waza(filename)
                elif offset_c0_bytes == b"\x00\x00\x00":
                    logging.info("Detected SVR06 WAZA format.")
                    return SVR06.parse_waza(filename)

                # Check offset 0x40 for HCTP
                file.seek(0x40)
                offset_40_bytes = file.read(3)
                if offset_40_bytes == b"\x04\x00\xFF":
                    logging.info("Detected HCTP format.")
                    return HCTP.parse_waza(filename)

                # If no known format is found
                raise ValueError(
                    "Unknown format: Could not detect a valid WAZA file format."
                )

        except FileNotFoundError:
            raise FileNotFoundError(f"File {filename} not found.")
        except Exception as e:
            raise RuntimeError(f"An error occurred while parsing the file: {str(e)}")
        finally:
            set_process_priority("NORMAL")


class YMIT:
    def __init__(self, root):
        self.root = root
        self.root.title("Yuke's Move Index Tool")
        self.config_path = os.path.join(
            os.getenv("LOCALAPPDATA"), "WCG847", "YMIT", "config", "config.json"
        )
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
                # Clear the treeview before populating
                self.clear_treeview()

                parsed_data = WazaParser.parse_waza(filename)
                self.populate_treeview(json.loads(parsed_data))
        except Exception as e:
            messagebox.showerror("Error", str(e))

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

    def deserialise_waza(self):
        self.moves = []  # Initialize moves to collect all move items
        def tree_to_structure(parent=""):
            children = self.treeview.get_children(parent)

            # If there are no children, process the current item
            if not children:
                values = self.treeview.item(parent, "values")
                if values and values[0]:
                    try:
                        set_process_priority("ABOVE_NORMAL")  # Ensure this is defined elsewhere
                        parsed_value = json.loads(values[0])
                        # Ensure parsed_value is a valid type
                        if isinstance(parsed_value, (dict, list, str, int, float, bool)):
                            return parsed_value
                        else:
                            return None  # Invalid parsed value
                    except json.JSONDecodeError:
                        return values[0]  # Return raw value if not JSON-parsable
                return None

            # If there are children, decide the structure
            result = {}
            for child in children:
                key = self.treeview.item(child, "text")
                value = tree_to_structure(child)

                # If key starts with "Item X", group into moves
                if key.startswith("Item "):
                    move_data = tree_to_structure(child)
                    if isinstance(move_data, dict):
                        self.moves.append(move_data)  # Collect move data in the class-level moves
                    continue

                # Skip unwanted keys like categories or total_moves
                if key in ("categories", "total_moves"):
                    continue

                # Handle parameters explicitly as a parent with child items
                if key == "parameters":
                    parameters_dict = {}
                    parameter_children = self.treeview.get_children(child)
                    for param_child in parameter_children:
                        param_key = self.treeview.item(param_child, "text")
                        param_value = self.treeview.item(param_child, "values")
                        parameters_dict[param_key] = int(param_value[0]) if param_value else 0
                    result[key] = parameters_dict
                    continue

                # Add other values to the result
                result[key] = value

            return result

        # Prompt user to save the file
        filename = filedialog.asksaveasfilename(
            title="Save JSON File",
            defaultextension=".json",
            filetypes=(("JSON files", "*.json"), ("All files", "*.*")),
        )
        if filename:
            try:
                # Generate data structure from treeview
                data = tree_to_structure()
                # Add moves to the root level of the data
                if self.moves:
                    data["moves"] = self.moves
                with open(filename, "w") as f:
                    json.dump(data, f, indent=4)  # Save JSON data to file
                messagebox.showinfo("Success", "File saved successfully.")
            except Exception as e:
                messagebox.showerror("Error", str(e))
            finally:
                set_process_priority("NORMAL")  # Ensure this is defined elsewhere

    def serialise_waza(self):
        category_names = SVR_HCTP_CATE_NAMES
        column_flag_map = COLUMN_FLAG_MAP
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

        set_process_priority("ABOVE_NORMAL")

        try:
            with open(input_json_filename, "r") as json_file:
                data = json.load(json_file)

            # Handle 'moves' as a list of dictionaries
            moves = data.get("moves", [])
            if not isinstance(moves, list):
                raise ValueError("'moves' must be a list in the JSON schema.")

            # Sort moves alphabetically by 'name'
            moves_list = sorted(moves, key=lambda move: move.get("name", "").lower())
            total_moves = len(moves_list)

            # Determine format from the parsed JSON header
            format_header = data.get("header", "SVR05")
            if format_header not in ["SVR05", "SVR06", "HCTP"]:
                raise ValueError(f"Unknown format header: {format_header}")

            if format_header == "SVR06":
                category_names = SVR06_CATE_NAMES

            # Initialize category_counts for all categories
            category_counts = {name: 0 for name in category_names}

            # Count the 'True' flags in category_flags for each move
            for move in moves_list:
                category_flags = move.get("category_flags", {})
            
                # Validate and ensure category_flags is a dictionary
                if isinstance(category_flags, str):
                    if category_flags.lower() == "dict":
                        category_flags = {}
                    else:
                        raise ValueError(
                            f"Expected 'category_flags' to be a dictionary or 'dict', got {type(category_flags).__name__}: {category_flags}"
                        )

                if not isinstance(category_flags, dict):
                    raise ValueError(
                        f"Expected 'category_flags' to be a dictionary, got {type(category_flags).__name__}: {category_flags}"
                    )

                # Count 'True' values for each category
                for category, is_flag_set in category_flags.items():
                    if category in category_counts and is_flag_set == "True":
                        category_counts[category] += 1


                # Replace the category_flags in the move with the validated version
                move["category_flags"] = category_flags


            with open(output_waza_filename, "wb") as binary_file:
                # Write header and pads
                binary_file.write(b"\xFF\x00\x00\x00")
                binary_file.write(struct.pack("<H", total_moves))
                binary_file.write(b"\x00\x00")

                if format_header == "SVR05" or format_header == "SVR06":
                    # Write category counts to the binary file
                    for category in category_names:
                        binary_file.write(struct.pack("<H", category_counts[category]))
                    binary_file.write(struct.pack("<H", 0xFFFF))  # EOCM

                elif format_header == "HCTP":
                    binary_file.write(b"\x00" * 8)

                # Serialize each move
                for i, move in enumerate(moves_list):
                    if format_header == "HCTP" and i == 0:
                        # First move in HCTP: no move header
                        pass
                    else:
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

                    # Serialize move name
                    move_name = move.get("name", "Unknown")
                    name_length = 32 if format_header in ["SVR05", "HCTP"] else 96
                    binary_file.write(move_name.ljust(name_length, "\x00")[:name_length].encode("utf-8"))

                    # Serialize damage flags
                    damage_flags = move.get("damage_flags", {})
                    binary_file.write(
                        struct.pack(
                            "<3B",
                            damage_flags.get("unknown_flag", 0),
                            damage_flags.get("damage_value", 0),
                            damage_flags.get("exclusive_id", 0),
                        )
                    )

                    # Serialize column flags and parameters
                    column_flag_byte = 0x00
                    column_flags = move.get("column_flags", {})
                    if isinstance(column_flags, dict):
                        for key, value in column_flags.items():
                            if value and key in column_flag_map.values():
                                column_flag_byte = list(column_flag_map.keys())[
                                    list(column_flag_map.values()).index(key)
                                ]
                                break

                    unlock_id = move.get("unlock_id", 0)
                    unlock_id_2 = move.get("unlock_id_2", 0)
                    # Extract parameters
                    parameters = move.get("parameters", {})
                    parameters_values = [parameters.get(f"Item {i}", 0) for i in range(18)]

                    # Combine with flags
                    parameters_with_flags = [
                        column_flag_byte,
                        unlock_id,
                        unlock_id_2,
                        *parameters_values,
                    ]

                    # Write parameters based on the format
                    if format_header in ["SVR05", "HCTP"]:
                        # Only the first 5 items are used for SVR05 and HCTP
                        binary_file.write(struct.pack("<5B", *parameters_with_flags[:5]))
                    elif format_header == "SVR06":
                        # All 21 items are used for SVR06
                        binary_file.write(struct.pack("<21B", *parameters_with_flags))


                    # Serialize move ID
                    move_id = move.get("id", 0)
                    binary_file.write(struct.pack("<H", move_id))

            messagebox.showinfo(
                "Serialization Complete", f"Output saved to {output_waza_filename}"
            )
        except Exception as e:
            messagebox.showerror("Error", str(e))
        finally:
            set_process_priority("NORMAL")


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