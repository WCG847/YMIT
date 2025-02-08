def sanitise_move_name(raw_name):
    """
    Sanitises the move name by:
    - Trimming at the first occurrence of 0x00 (null terminator).
    - Removing trailing spaces added as padding.
    """
    if raw_name:
        return raw_name.split("\x00", 1)[0].strip()
    return ""