from WAZA.Utilities.LUT import SVR_HCTP_CATE_NAMES, COLUMN_FLAG_MAP
from WAZA.Utilities.Misc import sanitise_move_name
import json
import struct

class HCTP:
    @staticmethod
    def parse_waza(filename):
        """
        Parses HCTP Move Format
        """
        category_names = SVR_HCTP_CATE_NAMES
        column_flag_map = COLUMN_FLAG_MAP

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

        return json.dumps(parsed_data, indent=4)