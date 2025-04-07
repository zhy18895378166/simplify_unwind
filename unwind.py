import sys
import struct
from collections import namedtuple
import subprocess
import shlex
from typing import Union, Optional, Tuple, List
import re

# 定义指令类型
DwarfInstruction = namedtuple('DwarfInstruction', ['opcode', 'args', 'offset'])

# DWARF 标准帧指令操作码
DW_CFA_advance_loc = 0x40
DW_CFA_offset = 0x80
DW_CFA_restore = 0xC0
DW_CFA_nop = 0x00
DW_CFA_set_loc = 0x01
DW_CFA_advance_loc1 = 0x02
DW_CFA_advance_loc2 = 0x03
DW_CFA_advance_loc4 = 0x04
DW_CFA_offset_extended = 0x05
DW_CFA_restore_extended = 0x06
DW_CFA_undefined = 0x07
DW_CFA_same_value = 0x08
DW_CFA_register = 0x09
DW_CFA_remember_state = 0x0A
DW_CFA_restore_state = 0x0B
DW_CFA_def_cfa = 0x0C
DW_CFA_def_cfa_register = 0x0D
DW_CFA_def_cfa_offset = 0x0E
# ... 可以添加更多操作码

# def parse_uleb128(data, offset):
    # """解析无符号 LEB128 编码"""
    # result = 0
    # shift = 0
    # while True:
        # byte = data[offset]
        # offset += 1
        # result |= (byte & 0x7f) << shift
        # if not (byte & 0x80):
            # break
        # shift += 7
    # return result, offset

# def parse_sleb128(data, offset):
    # """解析有符号 LEB128 编码"""
    # result = 0
    # shift = 0
    # while True:
        # byte = data[offset]
        # offset += 1
        # result |= (byte & 0x7f) << shift
        # shift += 7
        # if not (byte & 0x80):
            # break
    # if byte & 0x40 and shift < (8 * 8):  # 符号扩展
        # result |= (~0 << shift)
    # return result, offset

# def parse_fde_instructions(data, offset, length):
    # """解析 FDE 中的指令序列
    
    # 参数:
        # data: 包含 FDE 的二进制数据
        # offset: 指令开始的偏移量
        # length: 指令序列的长度
        
    # 返回:
        # instructions: 解析出的指令列表
        # new_offset: 解析后的新偏移量
    # """
    # instructions = []
    # end_offset = offset + length
    
    # while offset < end_offset:
        # opcode = data[offset]
        # offset += 1
        # args = []
        
        # # 解析指令参数
        # if opcode == DW_CFA_nop:
            # pass
        # elif opcode == DW_CFA_set_loc:
            # # 4/8 字节地址 (取决于地址大小)
            # loc = struct.unpack_from('<Q', data, offset)[0]
            # args.append(loc)
            # offset += 8
        # elif opcode == DW_CFA_advance_loc1:
            # delta = data[offset]
            # args.append(delta)
            # offset += 1
        # elif opcode == DW_CFA_advance_loc2:
            # delta = struct.unpack_from('<H', data, offset)[0]
            # args.append(delta)
            # offset += 2
        # elif opcode == DW_CFA_advance_loc4:
            # delta = struct.unpack_from('<I', data, offset)[0]
            # args.append(delta)
            # offset += 4
        # elif opcode == DW_CFA_offset_extended:
            # reg, offset = parse_uleb128(data, offset)
            # offset_val, offset = parse_uleb128(data, offset)
            # args.extend([reg, offset_val])
        # elif opcode == DW_CFA_def_cfa:
            # reg, offset = parse_uleb128(data, offset)
            # offset_val, offset = parse_uleb128(data, offset)
            # args.extend([reg, offset_val])
        # elif opcode == DW_CFA_def_cfa_register:
            # reg, offset = parse_uleb128(data, offset)
            # args.append(reg)
        # elif opcode == DW_CFA_def_cfa_offset:
            # offset_val, offset = parse_uleb128(data, offset)
            # args.append(offset_val)
        # elif (opcode & 0xC0) == DW_CFA_advance_loc:
            # delta = opcode & 0x3F
            # args.append(delta)
        # elif (opcode & 0xC0) == DW_CFA_offset:
            # reg = opcode & 0x3F
            # offset_val, offset = parse_uleb128(data, offset)
            # args.extend([reg, offset_val])
        # elif (opcode & 0xC0) == DW_CFA_restore:
            # reg = opcode & 0x3F
            # args.append(reg)
        # else:
            # # 未知操作码，跳过或报错
            # raise ValueError(f"Unknown DWARF CFA opcode: 0x{opcode:02x}")
        
        # instructions.append(DwarfInstruction(opcode, args, offset - 1))
    
    # return instructions, offset


# def get_cfa_rules(instructions, target_pc, initial_loc, code_alignment_factor):
    # """从指令序列中提取 CFA 规则
    
    # 参数:
        # instructions: 解析出的指令列表
        # target_pc: 目标程序计数器值
        # initial_loc: FDE 的初始位置
        # code_alignment_factor: CIE 中的代码对齐因子
        
    # 返回:
        # cfa_rule: CFA 规则 (reg, offset) 或 None
    # """
    # current_pc = initial_loc
    # cfa_rule = None
    
    # for instr in instructions:
        # # 处理 PC 前进指令
        # if instr.opcode == DW_CFA_advance_loc1:
            # current_pc += instr.args[0] * code_alignment_factor
        # elif instr.opcode == DW_CFA_advance_loc2:
            # current_pc += instr.args[0] * code_alignment_factor
        # elif instr.opcode == DW_CFA_advance_loc4:
            # current_pc += instr.args[0] * code_alignment_factor
        # elif (instr.opcode & 0xC0) == DW_CFA_advance_loc:
            # current_pc += (instr.opcode & 0x3F) * code_alignment_factor
        # elif instr.opcode == DW_CFA_set_loc:
            # current_pc = instr.args[0]
        
        # # 如果当前PC超过目标PC，停止处理
        # if current_pc > target_pc:
            # break
            
        # # 处理CFA相关指令
        # if instr.opcode == DW_CFA_def_cfa:
            # cfa_rule = ('reg_offset', instr.args[0], instr.args[1])
        # elif instr.opcode == DW_CFA_def_cfa_register:
            # if cfa_rule and cfa_rule[0] == 'reg_offset':
                # cfa_rule = ('reg_offset', instr.args[0], cfa_rule[2])
        # elif instr.opcode == DW_CFA_def_cfa_offset:
            # if cfa_rule and cfa_rule[0] == 'reg_offset':
                # cfa_rule = ('reg_offset', cfa_rule[1], instr.args[0])
    
    # return cfa_rule

def decode_leb128(byte_stream, signed=False):
    """通用 LEB128 解码，通过 signed 参数区分"""
    value = 0
    shift = 0
    size = 32  # 或 64，根据目标平台调整
    byte = 0
    
    while True:
        byte = byte_stream.pop(0)
        value |= (byte & 0x7f) << shift
        shift += 7
        
        if (byte & 0x80) == 0:
            break
    
    # 如果是 SLEB128 且需要符号扩展
    if signed and (byte & 0x40):
        value |= - (1 << shift)

    #print("decode_leb128 value: 0x%x(%d)" %(value, value))
    return value

def shell(
    command: Union[str, List[str]],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    shell: bool = True,
    capture_output: bool = False,
    check: bool = False,
    input_data: Optional[Union[str, bytes]] = None,
    encoding: Optional[str] = 'utf-8',
    errors: Optional[str] = 'strict'
) -> Tuple[Optional[Union[str, bytes]], Optional[Union[str, bytes]], int]:
    command_str = command
    if isinstance(command, str) and not shell:
        command = shlex.split(command)
    
    # 旧版本兼容的 capture_output 实现
    stdout = subprocess.PIPE if capture_output else None
    stderr = subprocess.PIPE if capture_output else None
    
    try:
        result = subprocess.run(
            command,
            timeout=timeout,
            cwd=cwd,
            env=env,
            shell=shell,
            check=check,
            input=input_data,
            stdout=stdout,
            stderr=stderr,
            encoding=encoding if capture_output else None,
            errors=errors
        )
        
        if capture_output:
            return (result.stdout, result.stderr, result.returncode)
        return (None, None, result.returncode)
    
    except subprocess.TimeoutExpired as e:
        if hasattr(e, 'cmd') and e.process:
            e.process.kill()
        raise
    except Exception as e:
        print("cmd: ", command_str)
        raise e

def read_simplify_debug_frames(file_name):
    stdout, stderr, retcode = shell(
        "readelf -S a.out | grep -sw -A1 .eh_frame",
        check=False,
        capture_output=True
    )
    print(stdout)
    print(stderr)
    hex_pattern = '[0-9a-fA-F]'
    pattern = re.compile(r".*\.eh_frame\s+\w+\s+%s+\s+(?P<offset>%s+)\s+(?P<size>%s+)"
        %(hex_pattern, hex_pattern, hex_pattern))
    info = pattern.match(stdout.replace('\n', '')).groupdict()
    seek_offset = int(info['offset'], 16)
    size = int(info['size'], 16)

    f = open(file_name, 'rb')
    f.seek(0)
    byte_stream = list(f.read())
    f.close()
    return byte_stream

def read_fde_header(byte_stream):
    start = decode_leb128(byte_stream)
    size = decode_leb128(byte_stream)
    count = decode_leb128(byte_stream)
    print("start: 0x%x, size: 0x%x, count: %d" %(start, size, count))

def read_fde_instrctions():
    pass

def main():
    byte_stream = read_simplify_debug_frames('zhy.bin')
    while len(byte_stream) > 0:
        read_fde_header(byte_stream)
        read_fde_instrctions()

# 使用示例
# def test():
    # # 假设这是从ELF文件中提取的FDE指令数据
    # fde_instructions_data = bytes([
        # 0x0C,       # DW_CFA_def_cfa
        # 0x07,       # register 7 (RSP)
        # 0x08,       # offset 8
        # 0x42,       # DW_CFA_advance_loc (delta=2)
        # 0x0E,       # DW_CFA_def_cfa_offset
        # 0x10,       # new offset 16
        # 0x00        # DW_CFA_nop
    # ])
    
    # # 解析指令
    # instructions, _ = parse_fde_instructions(fde_instructions_data, 0, len(fde_instructions_data))
    
    # # 打印解析结果
    # print("Parsed instructions:")
    # for instr in instructions:
        # print(f"0x{instr.opcode:02x} at offset {instr.offset}: args={instr.args}")
    
    # # 获取特定PC的CFA规则
    # target_pc = 0x1000
    # initial_loc = 0x1000
    # code_alignment_factor = 1
    # cfa_rule = get_cfa_rules(instructions, target_pc, initial_loc, code_alignment_factor)
    
    # print(f"\nCFA rule at PC 0x{target_pc:x}: {cfa_rule}")

if __name__ == "__main__":
    main()