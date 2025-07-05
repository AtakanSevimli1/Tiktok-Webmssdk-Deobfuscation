import json
import struct

# --- File Loading ---
with open('opcode_map.json', 'r') as f:
    opcode_map = json.load(f)

with open('bytecode.json', 'r') as f:
    bytecode_data = json.load(f)

# --- Bytecode Parsing ---
# The bytecode is a dictionary mapping string indices to byte values.
# We need to convert it into an ordered list.
# 1. Get dictionary items: [('0', 0), ('1', 45), ...]
# 2. Sort by the integer value of the key to ensure correct order.
# 3. Extract just the byte values into a list.
try:
    sorted_items = sorted(bytecode_data.items(), key=lambda item: int(item[0]))
    bytecode = [item[1] for item in sorted_items]
except (AttributeError, ValueError):
    print("Error: bytecode.json does not seem to be a dictionary of 'index': value. Please check the file format.")
    exit(1)


# --- VM State and Disassembly ---
ip = 0 # Instruction Pointer
output_lines = []

def read_bytes(size):
    """Reads 'size' bytes from the bytecode stream and advances the IP."""
    global ip
    if ip + size > len(bytecode):
        raise IndexError(f"Unexpected end of bytecode stream at ip={ip} trying to read {size} bytes.")
    
    data = bytecode[ip : ip + size]
    ip += size
    return data

def read_u16():
    """Reads a 16-bit unsigned integer (2 bytes) in little-endian format."""
    b = read_bytes(2)
    # The bytecode is a list of integers, so we need to convert them to bytes
    return struct.unpack('<H', bytes(b))[0] 

def read_u24():
    """Reads a 24-bit unsigned integer (3 bytes) in little-endian format."""
    b = read_bytes(3) + [0] # Pad to 4 bytes for struct
    return struct.unpack('<I', bytes(b))[0]

def format_operand(operand_def):
    """Reads and formats a single operand based on its definition."""
    op_type = operand_def['type']
    op_name = operand_def['name']
    op_size = operand_def['size']
    
    value = 0
    if op_size == 16:
        value = read_u16()
    elif op_size == 24:
        value = read_u24()
    # Add other sizes if they appear in your opcode_map
    # e.g., elif op_size == 8: value = read_bytes(1)[0]
    else:
        byte_count = op_size // 8
        raw_bytes = read_bytes(byte_count)
        value = int.from_bytes(bytes(raw_bytes), 'little')

    if op_type == 'reg':
        return f"{op_name}: r{value}"
    elif op_type == 'jump_target':
        return f"target: 0x{value:06X}" # Padded for alignment
    else:
        return f"{op_name}: {value}"

# --- Main Disassembly Loop ---
while ip < len(bytecode):
    start_ip = ip
    
    # In this VM, opcodes are 16-bit wide.
    # The first byte is the opcode number, and the second is an unused/padding byte.
    opcode_val = bytecode[ip]
    ip += 2 # Advance past the opcode and its padding byte
    opcode_str = str(opcode_val)

    if opcode_str in opcode_map:
        instr_def = opcode_map[opcode_str]
        instr_name = instr_def['name']
        operands = instr_def.get('operands', [])
        
        operand_strs = []
        try:
            for op_def in operands:
                operand_strs.append(format_operand(op_def))
            
            line = f"0x{start_ip:04X}:  {instr_name.ljust(25)} {', '.join(operand_strs)}"
            output_lines.append(line)

        except IndexError as e:
            output_lines.append(f"0x{start_ip:04X}:  ERROR parsing operands for {instr_name}: {e}")
            break # Stop on error
    else:
        # Note: If an opcode takes operands, we won't know how many bytes to skip.
        # This is why filling out the opcode map is crucial.
        line = f"0x{start_ip:04X}:  UNKNOWN_OPCODE(0x{opcode_val:X} / {opcode_val})"
        output_lines.append(line)
        break

# --- Output ---
with open('disassembly.txt', 'w') as f:
    f.write('\n'.join(output_lines))

print("Disassembly complete. Check disassembly.txt")