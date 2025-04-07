import sys
import struct
from collections import namedtuple
import re
import pprint
import subprocess
import shlex
from typing import Union, Optional, Tuple, List

pp = pprint.PrettyPrinter(width=41)

# 定义指令类型
DwarfInstruction = namedtuple('DwarfInstruction', ['opcode', 'args', 'offset'])
pc_range_pattern = re.compile('pc=(?P<start>\w+)\.+(?P<end>\w+)')

def parse_one_instruction_x86_64_gcc(line):
    one_arg_pattern = '(?P<arg1>[+\-]?\d+)?'
    reg_offset_pattern = '((?P<reg_name>\w+) \(\w+\) at cfa(?P<offset>[+\-]\d+))?'
    expression_pattern = '(\((?P<expression>.*)\))?'
    pattern = '(?P<name>DW_CFA_\w+):?\s*%s%s%s' %(one_arg_pattern, reg_offset_pattern, expression_pattern)

    m = re.match(pattern, line)
    if m:
        #print(m.groupdict())
        return m.groupdict()
    return None

###########################################  tool functions  ###############################
class DictWrapper:
    def __init__(self, dictionary):
        self._dict = dictionary

    def __getattr__(self, name):
        if name in self._dict:
            return self._dict[name]
        else:
            raise AttributeError(f"Attribute '{name}' does not exist.")

def encode_uleb128(value):
    """Encode an unsigned integer into ULEB128 format."""
    if value < 0:
        raise ValueError("ULEB128 can only encode non-negative integers")
    
    bytes_ = []
    while True:
        byte = value & 0x7f
        value >>= 7
        if value != 0:
            byte |= 0x80
        bytes_.append(byte)
        if value == 0:
            break
    return bytes_

def encode_sleb128(value):
    """Encode a signed integer into SLEB128 format."""
    bytes_ = []
    more = True
    
    while more:
        byte = value & 0x7f
        value >>= 7
        # 符号位扩展
        if (value == 0 and (byte & 0x40) == 0) or (value == -1 and (byte & 0x40)):
            more = False
        else:
            byte |= 0x80
        bytes_.append(byte)
    
    return bytes_

def shell(
    command: Union[str, List[str]],
    timeout: Optional[int] = None,
    cwd: Optional[str] = None,
    env: Optional[dict] = None,
    shell: bool = False,
    capture_output: bool = False,
    check: bool = False,
    input_data: Optional[Union[str, bytes]] = None,
    encoding: Optional[str] = 'utf-8',
    errors: Optional[str] = 'strict'
) -> Tuple[Optional[Union[str, bytes]], Optional[Union[str, bytes]], int]:
    """
    执行Shell命令并返回结果
    
    参数:
        command: 要执行的命令，可以是字符串或列表
        timeout: 超时时间(秒)
        cwd: 工作目录
        env: 环境变量字典
        shell: 是否通过shell执行
        capture_output: 是否捕获输出
        check: 如果命令返回非零状态码是否抛出异常
        input_data: 输入到命令的数据
        encoding: 输入/输出的编码
        errors: 编码错误处理方式
    
    返回:
        元组(stdout, stderr, returncode)
        如果capture_output为False，则stdout和stderr为None
    
    异常:
        subprocess.TimeoutExpired: 命令执行超时
        subprocess.CalledProcessError: check=True且返回码非零时抛出
    """
    # 如果command是字符串且shell=False，则自动分割参数
    if isinstance(command, str) and not shell:
        command = shlex.split(command)
    
    try:
        result = subprocess.run(
            command,
            timeout=timeout,
            cwd=cwd,
            env=env,
            shell=shell,
            check=check,
            input=input_data,
            capture_output=capture_output,
            encoding=encoding if capture_output else None,
            errors=errors
        )
        
        if capture_output:
            return (result.stdout, result.stderr, result.returncode)
        return (None, None, result.returncode)
    
    except subprocess.TimeoutExpired as e:
        # 超时时尝试终止进程
        if hasattr(e, 'cmd') and e.process:
            e.process.kill()
        raise
    except Exception as e:
        raise e


###########################################  common code  ##################################
# DWARF 标准帧指令操作码
opcode = DictWrapper({
    'DW_CFA_advance_loc': 0x40,
    'DW_CFA_offset': 0x80,
    'DW_CFA_restore': 0xC0,
    'DW_CFA_nop': 0x00,
    'DW_CFA_set_loc': 0x01,
    'DW_CFA_advance_loc1': 0x02,
    'DW_CFA_advance_loc2': 0x03,
    'DW_CFA_advance_loc4': 0x04,
    'DW_CFA_offset_extended': 0x05,
    'DW_CFA_restore_extended': 0x06,
    'DW_CFA_undefined': 0x07,
    'DW_CFA_same_value': 0x08,
    'DW_CFA_register': 0x09,
    'DW_CFA_remember_state': 0x0A,
    'DW_CFA_restore_state': 0x0B,
    'DW_CFA_def_cfa': 0x0C,
    'DW_CFA_def_cfa_register': 0x0D,
    'DW_CFA_def_cfa_offset': 0x0E,
    # ... 可以添加更多操作码
})


def get_cie_or_fde_block(input_str, cie=False, fde=True):
    split_list = input_str.split('\n\n')
    if cie:
        frames = list(filter(lambda x: 'CIE' in x, split_list))
    elif fde:
        frames = list(filter(lambda x: 'FDE' in x, split_list))
    elif cie and fde:
        frames = list(filter(lambda x: 'CIE' in x or 'FDE' in x, split_list))

    #pp.pprint(frames)
    return frames

def parse_fde_head_line(head_line):
    split_list = head_line.split(' ')
    items = list(map(lambda x: x.strip(), split_list))
    print(items)

    # pc range
    if 'pc' in items[-1]:
        pc_range_text = items[-1]
    else:
        print('[ERROR] can not find pc range in FDE head line')
        sys.exit(-1)
    info = pc_range_pattern.match(pc_range_text).groupdict()

    return info

def parse_fde_instructions(inst_lines):
    instructions = []
    remove_insts = ['DW_CFA_nop']
    keep_regs_offset=['r6'] # DW_CFA_offset 

    # remove no need instruction
    for l in inst_lines:
        inst = parse_one_instruction_x86_64_gcc(l)
        if inst and inst['name'] not in remove_insts:
            if inst['name'] != 'DW_CFA_offset' or inst['reg_name'] in keep_regs_offset:
                instructions.append(inst)
                print(inst)
    
    #print(instructions)
    return instructions

def parse_fde(fde_text):
    split_list = fde_text.split('\n')
    frame_lines = list(map(lambda x: x.strip(), split_list))
    #print(frame_lines)

    # parse FDE head line
    parsed_fde = parse_fde_head_line(frame_lines[0])

    # parse instruction line
    insts = parse_fde_instructions(frame_lines[1:])
    parsed_fde['instructions'] = insts
    #print(parsed_fde)
    
    return parsed_fde

def init_write_to_bin(bin_name, seek_offset=0):
    f = open(bin_name, 'r+b')
    if seek_offset > 0:
        f.seek(seek_offset)
    return f

def pack_instruction(inst_dict):
    pass
    

def encode_simplify_dwarf_to_bin(fo, fde_dict):
    start = int(fde_dict['start'], 16)
    end = int(fde_dict['end'], 16)
    size = end - start
    count = len(fde_dict['instructions'])
    print("start: 0x%x, size: 0x%x, count: %d" %(start, size, count))
    
    def pack_data(data):
        func = encode_uleb128
        if data < 0:
            func = encode_sleb128
        pack_data = func(data)

        print(pack_data)
        fmt = f'{len(pack_data)}B'
        byte_stream = struct.pack(fmt, *pack_data)
        fo.write(byte_stream)

    # pack header info
    pack_data(start)
    pack_data(size)
    pack_data(count)
    
    # pack instructions 
    for inst in fde_dict['instructions']:
        pack_instruction(DictWrapper(inst))

def test_exe_fde_instructions(fde, target_pc):
    current_pc = int(fde.start, 16)
    instructions = fde.instructions
    cfa_rule = None
    
    for instr in instructions:
        instr = DictWrapper(instr)
        # 处理 PC 前进指令
        if instr.name == 'DW_CFA_advance_loc1':
            current_pc += instr.args[0] * code_alignment_factor
        elif instr.name == 'DW_CFA_advance_loc2':
            current_pc += instr.args[0] * code_alignment_factor
        elif instr.name == 'DW_CFA_advance_loc4':
            current_pc += instr.args[0] * code_alignment_factor
        elif (instr.name & 0xC0) == 'DW_CFA_advance_loc':
            current_pc += (instr.name & 0x3F) * code_alignment_factor
        elif instr.name == 'DW_CFA_set_loc':
            current_pc = instr.args[0]
        
        # 如果当前PC超过目标PC，停止处理
        print("current_pc: ", current_pc)
        if current_pc > target_pc:
            break
            
        # 处理CFA相关指令
        if instr.name == DW_CFA_def_cfa:
            cfa_rule = ('reg_offset', instr.args[0], instr.args[1])
        elif instr.name == DW_CFA_def_cfa_register:
            if cfa_rule and cfa_rule[0] == 'reg_offset':
                cfa_rule = ('reg_offset', instr.args[0], cfa_rule[2])
        elif instr.name == DW_CFA_def_cfa_offset:
            if cfa_rule and cfa_rule[0] == 'reg_offset':
                cfa_rule = ('reg_offset', cfa_rule[1], instr.args[0])
    
    return cfa_rule

def main():
    content = None
    fo = init_write_to_bin('zhy.bin')

    with open('zhy.txt', 'r') as f:
        content = f.read()

    frames = get_cie_or_fde_block(content)
    for fde in frames:
        parsed_fde = parse_fde(fde)

        # 使用uleb128/sleb128编码并写入bin文件
        if len(parsed_fde['instructions']) > 0:
            encode_simplify_dwarf_to_bin(fo, parsed_fde)
        
        target_pc = 0x6a0
        if target_pc > int(parsed_fde['start'], 16) and target_pc < int(parsed_fde['end'], 16):
            test_exe_fde_instructions(DictWrapper(parsed_fde), target_pc)
        
        input("*********************")
    
    fo.close()


# 使用示例
def test():
    # 假设这是从ELF文件中提取的FDE指令数据
    fde_instructions_data = bytes([
        0x0C,       # DW_CFA_def_cfa
        0x07,       # register 7 (RSP)
        0x08,       # offset 8
        0x42,       # DW_CFA_advance_loc (delta=2)
        0x0E,       # DW_CFA_def_cfa_offset
        0x10,       # new offset 16
        0x00        # DW_CFA_nop
    ])
    
    # 解析指令
    instructions, _ = parse_fde_instructions(fde_instructions_data, 0, len(fde_instructions_data))
    
    # 打印解析结果
    print("Parsed instructions:")
    for instr in instructions:
        print(f"0x{instr.opcode:02x} at offset {instr.offset}: args={instr.args}")
    
    # 获取特定PC的CFA规则
    target_pc = 0x1000
    initial_loc = 0x1000
    code_alignment_factor = 1
    cfa_rule = get_cfa_rules(instructions, target_pc, initial_loc, code_alignment_factor)
    
    print(f"\nCFA rule at PC 0x{target_pc:x}: {cfa_rule}")

if __name__ == "__main__":
    main()