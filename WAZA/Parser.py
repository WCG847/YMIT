import struct
from WAZA.SVR05.WAZA import *
from WAZA.SVR06.WAZE import *
from WAZA.HCTP.WAZA import *

class WazaParser:
    @staticmethod
    def parse_waza(filename):
        """
        Determines the format of the WAZA file and parses it accordingly.
        """

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

                # Check for specific formats based on offsets
                # Check offset 0xC0 for SVR05 or SVR06
                file.seek(0xC0)
                offset_c0_bytes = file.read(3)
                if offset_c0_bytes == b"\x03\x0A\xFF":
                    return SVR05.parse_waza(filename)
                elif offset_c0_bytes == b"\x00\x00\x00":
                    return SVR06.parse_waza(filename)

                # Check offset 0x40 for HCTP
                file.seek(0x40)
                offset_40_bytes = file.read(3)
                if offset_40_bytes == b"\x04\x00\xFF":
                    return HCTP.parse_waza(filename)

                # If no known format is found
                raise ValueError(
                    "Unknown format: Could not detect a valid WAZA file format."
                )

        except FileNotFoundError:
            raise FileNotFoundError(f"File {filename} not found.")
        except Exception as e:
            raise RuntimeError(f"An error occurred while parsing the file: {str(e)}")