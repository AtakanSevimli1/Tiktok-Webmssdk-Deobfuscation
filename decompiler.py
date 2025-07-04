import json
import sys

def decompile(bytecode_path, string_table_path, opcode_map_path, output_path):
    """
    Decompiles the VM bytecode into a human-readable assembly-like format.
    """
    try:
        with open(bytecode_path, 'r') as f:
            bytecode_data = json.load(f)
        
        with open(string_table_path, 'r', encoding='utf-8') as f:
            string_table = json.load(f)
            
        with open(opcode_map_path, 'r') as f:
            opcode_map = json.load(f)

    except FileNotFoundError as e:
        print(f"Error: Could not open a required file. {e}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Could not parse JSON file '{e.docpath}'. {e}")
        sys.exit(1)

    # --- FIX: Convert bytecode dictionary to a list if necessary ---
    if isinstance(bytecode_data, dict):
        print("Bytecode is a dictionary. Converting to a sorted list.")
        # Sort items based on the integer value of their keys
        try:
            sorted_items = sorted(bytecode_data.items(), key=lambda item: int(item[0]))
            bytecode = [item[1] for item in sorted_items]
        except (ValueError, TypeError):
            print("Error: Bytecode dictionary keys are not valid integers. Cannot sort.")
            sys.exit(1)
    elif isinstance(bytecode_data, list):
        bytecode = bytecode_data
    else:
        print(f"Error: Unsupported bytecode format '{type(bytecode_data)}'. Expected list or dict.")
        sys.exit(1)
    # --- END FIX ---

    ip = 0  # Instruction Pointer
    output_lines = []
    
    def read_op(size_in_bytes):
        nonlocal ip
        if ip + size_in_bytes > len(bytecode):
            raise IndexError("Unexpected end of bytecode stream.")
        
        if size_in_bytes == 1:
            val = bytecode[ip]
        elif size_in_bytes == 2:
            val = (bytecode[ip] << 8) | bytecode[ip + 1]
        elif size_in_bytes == 3:
            val = (bytecode[ip] << 16) | (bytecode[ip + 1] << 8) | bytecode[ip + 2]
        else:
            raise ValueError(f"Invalid operand size: {size_in_bytes}")
            
        ip += size_in_bytes
        return val

    def read_op8(): return read_op(1)
    def read_op16(): return read_op(2)
    def read_op24(): return read_op(3)

    operand_readers = {8: read_op8, 16: read_op16, 24: read_op24}

    while ip < len(bytecode):
        address = ip
        
        try:
            opcode_val = read_op16()
            opcode_str = str(opcode_val)
        except IndexError:
            break

        if opcode_str in opcode_map:
            instruction = opcode_map[opcode_str]
            name = instruction.get("name", f"OP_{opcode_str}")
            operands = instruction.get("operands", [])
            
            operand_values = []
            for op_info in operands:
                size = op_info["size"]
                op_type = op_info["type"]
                op_name = op_info.get("name", "")

                if size in operand_readers:
                    val = operand_readers[size]()
                    if op_type == "string_idx":
                        string_val = string_table[val] if val < len(string_table) else "INVALID_INDEX"
                        operand_values.append(f'{op_name}:STR[{val}] ({repr(string_val)})')
                    elif op_type == "jump_target":
                        operand_values.append(f'{op_name}:0x{val:X}')
                    else:
                        operand_values.append(f'{op_name}:{val}')
                else:
                    operand_values.append(f"INVALID_OP_SIZE({size})")

            output_lines.append(f"[{address:05X}] {name:<25} {', '.join(operand_values)}")
        
        else:
            output_lines.append(f"[{address:05X}] UNKNOWN_OP_{opcode_val}")

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    print(f"Decompilation complete. Output written to {output_path}")

if __name__ == "__main__":
    decompile(
        bytecode_path="bytecode.json", 
        string_table_path="string_table.json",
        opcode_map_path="opcode_map.json",
        output_path="deobfuscated_assembly.txt"
    )