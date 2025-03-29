# Function to convert decimal to hex UID with little-endian correction
def decimal_to_hex_uid(decimal_uid):
    # Convert decimal to hex, remove '0x', and pad with zeros
    hex_uid = hex(decimal_uid)[2:].upper().zfill(8)

    # Reverse byte order for little-endian conversion
    reversed_uid = ''.join(reversed([hex_uid[i:i+2] for i in range(0, len(hex_uid), 2)]))

    # Format as colon-separated bytes
    formatted_uid = ':'.join(reversed_uid[i:i+2] for i in range(0, len(reversed_uid), 2))
    return formatted_uid

# Get input from user
decimal_uid = int(input("Enter the Decimal UID: "))

# Convert and display the result
hex_uid = decimal_to_hex_uid(decimal_uid)
print(f"Hexadecimal UID: {hex_uid}")
