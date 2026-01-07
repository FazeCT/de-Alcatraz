import argparse
import sys
import os
import lief

from capstone import *
from keystone import *

class Deobfuscator:
    def __init__(self, input_path, output_path, section_name=None, verbose=False):
        self.input_path = input_path
        self.output_path = output_path
        self.verbose = verbose
        
        try:
            self.binary = lief.parse(self.input_path)
        except lief.parser.parser_error:
            print(f"[-] Error: Failed to parse input file: {self.input_path}")
            sys.exit(1)

        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        
        self.image_base = self.binary.optional_header.imagebase
        
        if section_name is None:
            print("[+] No section specified. Default to .text section...")
            section_name = '.text'

        self.section = self.binary.get_section(section_name)
        
        if not self.section:
            print(f"[-] Error: Section '{section_name}' not found in binary.")
            sys.exit(1)
   
        self.section_rva = self.section.virtual_address
        self.start_va = self.image_base + self.section_rva + 8
        self.content = bytearray(self.section.content)[8:]
        self.calls_done = {}

    def _log(self, message):
        if self.verbose:
            print(message)

    def _get_instructions(self):
        return list(self.cs.disasm(self.content, self.start_va))

    def _patch(self, address, bytes_list):
        self.binary.patch_address(address, bytes_list)
        
        offset = address - self.start_va
        if 0 <= offset < len(self.content):
            for i, b in enumerate(bytes_list):
                if offset + i < len(self.content):
                    self.content[offset + i] = b

    def remove_garbages(self):
        print(f"\n[+] Removing junk instructions...")
        offset = 0
        count = 0
        
        while offset < len(self.content):
            try:
                ins = next(self.cs.disasm(self.content[offset:], self.start_va + offset, count=1))
            except StopIteration:
                offset += 1
                continue

            if ins.bytes == b'\xEB\xFF':
                self._log(f"    [!] Patched jmp+1 at 0x{ins.address:X}")
                self._patch(ins.address, [0x90])
                offset += 1
                count += 1
                continue

            elif ins.mnemonic in ['popf', 'pushf']:
                self._log(f"    [!] Patched {ins.mnemonic} at 0x{ins.address:X}")
                self._patch(ins.address, [0x90] * ins.size)
                count += 1
            
            offset += ins.size
        print(f"[+] Removed {count} junk instructions.")

    def _rol(self, val, shift, bit_width):
        mask_shift = bit_width - 1
        shift &= mask_shift
        val_mask = (1 << bit_width) - 1
        return ((val << shift) & val_mask) | ((val & val_mask) >> (bit_width - shift))

    def _ror(self, val, shift, bit_width):
        mask_shift = bit_width - 1
        shift &= mask_shift
        val_mask = (1 << bit_width) - 1
        return ((val >> shift) & val_mask) | ((val & val_mask) << (bit_width - shift))

    def _calc_constant(self, start_offset, start_va, target_reg_id, initial_val, op_size):
        bit_width = op_size * 8
        val_mask = (1 << bit_width) - 1
        current_val = initial_val
        offset = start_offset
        bytes_consumed = 0
        ops_found = 0

        while offset < len(self.content):
            try:
                ins = next(self.cs.disasm(self.content[offset:], start_va + offset, count=1))
            except StopIteration:
                break

            if ins.mnemonic == 'nop':
                offset += ins.size
                bytes_consumed += ins.size
                continue

            if len(ins.operands) > 0 and ins.operands[0].type == CS_OP_REG and ins.operands[0].reg == target_reg_id:
                if ins.mnemonic == 'not':
                    current_val = (~current_val) & val_mask
                elif ins.mnemonic == 'add':
                    current_val = (current_val + ins.operands[1].imm) & val_mask
                elif ins.mnemonic == 'sub':
                    current_val = (current_val - ins.operands[1].imm) & val_mask
                elif ins.mnemonic == 'xor':
                    current_val = (current_val ^ ins.operands[1].imm) & val_mask
                elif ins.mnemonic == 'rol':
                    current_val = self._rol(current_val, ins.operands[1].imm, bit_width)
                elif ins.mnemonic == 'ror':
                    current_val = self._ror(current_val, ins.operands[1].imm, bit_width)
                else:
                    break
                
                ops_found += 1
                offset += ins.size
                bytes_consumed += ins.size
            else:
                break
        
        return current_val, bytes_consumed, ops_found

    def simplify_arithmetic_op(self):
        print(f"\n[+] Simplifying immediate calculation...")
        offset = 0
        count = 0

        while offset < len(self.content):
            try:
                ins = next(self.cs.disasm(self.content[offset:], self.start_va + offset, count=1))
            except StopIteration:
                offset += 1
                continue

            if (ins.mnemonic == 'mov' or ins.mnemonic == 'movabs') and len(ins.operands) == 2 and ins.operands[0].type == CS_OP_REG and ins.operands[1].type == CS_OP_IMM:
                target_reg_id = ins.operands[0].reg
                target_reg_name = ins.reg_name(target_reg_id)
                op_size = ins.operands[0].size
                initial_val = int(ins.operands[1].imm)
                
                final_val, consumed_bytes, ops_count = self._calc_constant(
                    offset + ins.size, self.start_va, target_reg_id, initial_val, op_size
                )

                if ops_count > 0:
                    new_asm = ""

                    if op_size == 8:
                        new_asm = f"movabs {target_reg_name}, {final_val}"
                    else:
                        new_asm = f"mov {target_reg_name}, {final_val}"
                    
                    try:
                        encoding, _ = self.ks.asm(new_asm)
                        total_block_size = ins.size + consumed_bytes
                        
                        if len(encoding) <= total_block_size:
                            nop_padding = [0x90] * (total_block_size - len(encoding))
                            patch_bytes = encoding + nop_padding
                            self._patch(ins.address, patch_bytes)
                            
                            self._log(f"    [!] Merged {ops_count} ops -> {new_asm} at 0x{ins.address:X}")
                            
                            offset += total_block_size
                            count += 1
                            continue
                        else:
                            if self.verbose:
                                print(f"    [!] Result larger than block at 0x{ins.address:X}")
                    except KsError as e:
                        print(f"Assembly error at 0x{ins.address:X}: {e}")

            offset += ins.size
        print(f"[+] Simplified {count} calculation chains.")

    def merge_tail_calls(self):
        print(f"\n[+] Resolving tail calls...")
        instructions = self._get_instructions()
        patches = []

        for i in range(len(instructions)):
            if instructions[i].mnemonic == 'call':
                curr_call_addr = instructions[i].address
                
                if instructions[i].operands[0].type == CS_OP_MEM:
                    continue

                try:
                    target_va = instructions[i].operands[0].imm
                except:
                    continue

                if target_va in self.calls_done:
                    real_function_va = self.calls_done[target_va]
                    patches.append({
                        'addr': curr_call_addr,
                        'target': real_function_va,
                    })
                    self._log(f"    [!] Call instruction at 0x{curr_call_addr:X} patched to call 0x{real_function_va:X}")
                    continue

                jmp_dst = target_va
                depth = 0x100
                
                while depth > 0:  
                    jmp_code = self.binary.get_content_from_virtual_address(jmp_dst, 15)
                    try:
                        first_ins = next(self.cs.disasm(jmp_code, jmp_dst, count=1))
                    except StopIteration:
                        break

                    if first_ins.mnemonic == 'jmp':
                        if first_ins.operands[0].type == CS_OP_IMM:
                            jmp_dst = first_ins.operands[0].imm
                            depth -= 1
                        else:
                            break
                    elif first_ins.mnemonic == 'nop':
                        jmp_dst += first_ins.size
                    else:
                        real_function_va = jmp_dst
                        
                        if real_function_va != target_va:
                            patches.append({
                                'addr': curr_call_addr,
                                'target': real_function_va,
                            })
                            self._log(f"    [!] Call instruction at 0x{curr_call_addr:X} patched to call 0x{real_function_va:X}")
                            self.calls_done[target_va] = real_function_va
                        break
                else:
                    print(f"Depth limit exceeded for call at 0x{curr_call_addr:X}. Change limit if needed.")

        for p in patches:
            call_offset = p['target'] - p['addr'] - 5
            ins = b'\xE8' + call_offset.to_bytes(4, 'little', signed=True)
            self._patch(p['addr'], [x for x in ins])
        
        print(f"[+] Resolved {len(patches)} calls instructions.")

    def _find_dispatcher(self):
        instructions = self._get_instructions()
        ls = []
        for i in range(len(instructions) - 5):
            ins_list = instructions[i:i+6]
            ins_mnemonics = [ins.mnemonic for ins in ins_list]
            
            if ins_mnemonics == ['cmp', 'jne', 'nop', 'nop', 'pop', 'jmp']:
                dispatcher_info = {}
                dispatcher_info['address'] = ins_list[0].address
                dispatcher_info['condition'] = ins_list[0].operands[1].imm
                dispatcher_info['true_offset'] = ins_list[5].operands[0].imm
                dispatcher_info['next_ins_addr'] = ins_list[5].address + ins_list[5].size
                ls.append(dispatcher_info)
        return ls

    def solve_cff(self):
        print(f"\n[+] Resolving CFF...")
        dispatcher_entries = self._find_dispatcher()
        disp_map = {d['address']: d for d in dispatcher_entries}
        
        if not disp_map:
            print(f"[-] No dispatcher patterns found in {self.section.name}.")
            return

        instructions = self._get_instructions()
        patches = []

        for i in range(len(instructions)):
            if instructions[i].mnemonic == 'push':
                curr_bridge_start = instructions[i].address
                mov_instr = None
                jmp_instr = None
                is_valid_bridge = False
                is_valid_bridge_no_jmp = None
                
                for j in range(i + 1, min(i + 100, len(instructions))):
                    instr = instructions[j]
                    
                    if instr.mnemonic == 'mov':
                        mov_instr = instr
                    elif instr.mnemonic == 'jmp':
                        jmp_instr = instr
                        break
                    elif instr.mnemonic == 'nop':
                        continue
                    elif instr.address in disp_map:
                        is_valid_bridge = True
                        is_valid_bridge_no_jmp = instr.address
                        break
                    else:
                        is_valid_bridge = False
                        break
                
                has_jmp_to_dispatcher = jmp_instr and (jmp_instr.operands[0].type == CS_OP_IMM) and (jmp_instr.operands[0].imm in disp_map)
                
                if (is_valid_bridge_no_jmp is not None) or has_jmp_to_dispatcher:
                    is_valid_bridge = True
                    target_addr = jmp_instr.operands[0].imm if jmp_instr else is_valid_bridge_no_jmp
                else:
                    is_valid_bridge = False

                if is_valid_bridge and mov_instr:
                    current_target = target_addr
                    
                    while current_target in disp_map:
                        dispatcher = disp_map[current_target]
                        bridge_val = mov_instr.operands[1].imm
                        
                        if bridge_val == dispatcher['condition']:
                            final_destination = dispatcher['true_offset']
                            patches.append({
                                'addr': curr_bridge_start,
                                'target': final_destination
                            })
                            self._log(f"    [!] 0x{curr_bridge_start:X} -> Dispatcher -> 0x{final_destination:X}")
                            break

                        current_target = disp_map[current_target]['next_ins_addr']
                        if current_target == target_addr: 
                            break

        for p in patches:
            jmp_offset = p['target'] - p['addr'] - 5
            ins = b'\xE9' + jmp_offset.to_bytes(4, 'little', signed=True)
            self._patch(p['addr'], [x for x in ins])

        print(f"[+] Resolved {len(patches)} CFF paths.")

    def run(self):
        print(f"[{self.section.name}]")

        self.remove_garbages()
        self.simplify_arithmetic_op()
        self.solve_cff()
        self.merge_tail_calls()
            
    def save(self):
        self.binary.write(self.output_path)
        print(f"\n[+] Finished.")

def main():
    parser = argparse.ArgumentParser(description="Deobfuscator for x64 PE binaries obfuscated by Alcatraz")
    parser.add_argument("-i", "--input", required=True, help="Input binary path")
    parser.add_argument("-o", "--output", required=False, help="Output binary path (Optional)")
    parser.add_argument("-s", "--section", required=False, help="Section name to deobfuscate (e.g., .text) - default to .text")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    if not args.output:
        base, extension = os.path.splitext(args.input)
        args.output = f"{base}_patched{extension}"

    obj = Deobfuscator(args.input, args.output, args.section, args.verbose)
    obj.run() 
    obj.save()
    
if __name__ == "__main__":
    main()
