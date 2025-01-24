def binary_to_c_array(file_path, array_name):
    with open(file_path, 'rb') as binary_file:
        binary_data = binary_file.read()

    # Create the C array representation
    c_array = f"unsigned char {array_name}[] = {{\n"
    c_array += ', '.join(f'0x{byte:02x}' for byte in binary_data)
    c_array += '\n};\n'
    
    return c_array

if __name__ == "__main__":
    binary_file_path = 'pubkey.der'
    array_name = 'pubkeyder'

    c_code = binary_to_c_array(binary_file_path, array_name)
    print(c_code)
