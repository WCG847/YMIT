import json
import struct

class SYM:
    @staticmethod
    def parse_waza(filename):
        """
        Parses SYM Move Format
        """

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

        return json.dumps(parsed_data, indent=4)