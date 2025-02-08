import json
from tkinter import filedialog, messagebox

def deserialise_waza(self):
    self.moves = []  # Initialize moves to collect all move items
    def tree_to_structure(parent=""):
        children = self.treeview.get_children(parent)

        # If there are no children, process the current item
        if not children:
            values = self.treeview.item(parent, "values")
            if values and values[0]:
                try:
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