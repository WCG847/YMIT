import json
import struct
from WAZA.Utilities.LUT import *
from tkinter import filedialog, messagebox

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