# YMIT: Yuke's Move Index Tool

### Overview
YMIT (Yuke's Move Index Tool) is a Python application to parse, visualise, and manage move index data from Yuke's WAZE/WAZA/CATE format used in virtually every last gen WWE game.

---

## Features

### File Operations
- **Parse Move Index Files**: Reads `.dat` files and extracts structured data, including categories and moves, into a tree view.
- **Serialise JSON to YMT format**: Converts edited JSON back to the `.dat` format.
- **Deserialise YMT to JSON**: Converts `.dat` files to JSON format for easier readability and editing.

### Visualisation
- Displays parsed `.dat` data in a tree view, allowing exploration of hierarchical structures like categories, moves, and their attributes.

### Error Handling
- Provides robust error handling with detailed logging, including:
  - File format validation.
  - JSON structure validation.
  - Comprehensive exception traceback in error messages.

### Logging
- Logs all critical events to a dedicated log file at `%LOCALAPPDATA%\WCG847\YMIT\logs\log.txt`.

---

## Installation

### Prerequisites
- Python 3.6 or higher
- `tkinter` (comes pre-installed with most Python distributions)

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/WCG847/YMIT.git
   cd YMIT
   ```
2. Run the application:
   ```bash
   python ymit.py
   ```

---

## Usage

### Main Features

1. **Open YMT File**:
   - Navigate to `File > Open` to select a `.dat` file.
   - Parsed data will be displayed in a tree view.

2. **Serialise JSON**:
   - Navigate to `JSON > Serialize` to convert a JSON file into a `.dat` file.

3. **Deserialise YMT**:
   - Navigate to `JSON > Deserialize` to save the current tree view structure as a JSON file.

---

## File Format Details

### Supported Formats
- `.dat` (Yuke's Move Table Format)
- `.json` (JavaScript Object Notation)

### Data Structure
- **Categories**: A mapping of 64 predefined categories to their respective values.
- **Moves**: Each move contains:
  - **Category Flags**: Identifies applicable categories for the move.
  - **Move Name**: A 32-character encoded string.
  - **Damage Flags**: Unknown flag, damage value, and exclusive ID.
  - **Parameters**: A set of 5 additional parameters.
  - **Move ID**: A unique identifier for the move.

---

## Logging

Logs are stored in:
```
%LOCALAPPDATA%\WCG847\YMIT\logs\log.txt
```
The log captures:
- File operations.
- Parsing errors.
- Serialisation and deserialisation errors.

---

## Contributing

### Reporting Issues
Feel free to submit issues via the [GitHub Issues](https://github.com/WCG847/YMIT/issues) page.

### Pull Requests
Contributions are welcome! Please ensure:
1. Code is well-documented.
2. Functionality is thoroughly tested.

---

## License

This project is licensed under the GPL 3.0 License. See the `LICENSE` file for details.

---

## Acknowledgments

Special thanks to ERM391, LOM, LGM, and the extended WWE Games Modding Community for the format specs of WAZA/WAZE