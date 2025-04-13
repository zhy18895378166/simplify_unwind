import re

flag = "<\d+><[0-9a-fA-F]+>"
g_die_pattern = re.compile(r'(%s.*?DW_TAG_\w+.*?)(?=\s+%s|$)'%(flag, flag), re.DOTALL)


class DotDict(dict):
    """
    支持点号访问的字典，可递归处理所有嵌套字典
    示例:
        d = AccessibleDict({'foo': {'bar': 42}})
        print(d.foo.bar)  # 输出 42
        d.foo.bar = 100
        print(d['foo']['bar'])  # 输出 100
    """
    
    def __init__(self, data=None):
        if data is None:
            data = {}
        super().__init__(data)
        # 递归转换所有字典值
        for key, value in data.items():
            if isinstance(value, dict):
                self[key] = AccessibleDict(value)
            elif isinstance(value, list):
                self[key] = [AccessibleDict(item) if isinstance(item, dict) else item for item in value]
    
    def __getattr__(self, key):
        try:
            value = self[key]
            if isinstance(value, dict) and not isinstance(value, AccessibleDict):
                value = AccessibleDict(value)
                self[key] = value
            return value
        except KeyError:
            raise AttributeError(f"'AccessibleDict' object has no attribute '{key}'")
    
    def __setattr__(self, key, value):
        if isinstance(value, dict):
            value = AccessibleDict(value)
        elif isinstance(value, list):
            value = [AccessibleDict(item) if isinstance(item, dict) else item for item in value]
        self[key] = value
    
    def __delattr__(self, key):
        try:
            del self[key]
        except KeyError:
            raise AttributeError(f"'AccessibleDict' object has no attribute '{key}'")
    
    def to_dict(self):
        """将AccessibleDict转换回普通字典"""
        result = {}
        for key, value in self.items():
            if isinstance(value, AccessibleDict):
                result[key] = value.to_dict()
            elif isinstance(value, list):
                result[key] = [item.to_dict() if isinstance(item, AccessibleDict) else item for item in value]
            else:
                result[key] = value
        return result

def get_compilation_uint(content):
    sep = 'Compilation Unit'
    pattern = re.compile(r'(%s.*?)(?=%s|$)' %(sep, sep), re.DOTALL)
    cus = pattern.findall(content)
    #print(cus)
    return cus


def get_function_dies(dies):
    func_tag = 'DW_TAG_subprogram'
    arg_tag = 'DW_TAG_formal_parameter'

    f = filter(lambda x: func_tag in x or arg_tag in x, dies)
    return list(f)


def get_func_or_arg_name(die, pattern, debug=False, trace=False):
    match = pattern.search(die)
    if match:
        if trace: print(match.group(0))
        func_start = 'DW_TAG_subprogram' in die
        return func_start, match.group(1)
    return False, ''

def get_low_pc(die, pattern, debug=False, trace=False):
    match = pattern.search(die)
    if match:
        if trace: print(match.group(0))
        return  int(match.group(1), 16)
    return ''

def get_cu_func_info(func_dies, debug=False, trace=False):
    #name_pattern = re.compile("^<[0-9a-fA-F]+>.*?DW_AT_name.*?:\s+(\w+)\n", re.DOTALL)
    name_pattern = re.compile("DW_AT_name.*?:\s+(\w+)\n", re.DOTALL)
    low_pc_pattern = re.compile("DW_AT_low_pc\s+:\s+(0x[0-9a-fA-F]+)\n", re.DOTALL)
    cu_func_info = []
    func = DotDict({})
    cu_func_info_dict = {}

    for die in func_dies:
        isStart, name = get_func_or_arg_name(die, name_pattern, debug, trace)
        if trace: print(name)
        if isStart:
            #print(re.search(low_pc_p, die)[0])
            if func != {}:
                func.argc = len(func.args_name)
                cu_func_info.append(func)
                cu_func_info_dict[func.start] = func
                if trace: print(func)

            func = DotDict({})
            func.name = name
            func.start = get_low_pc(die, low_pc_pattern, debug, trace)
            func.args_name = []
        else:
            func.args_name.append(name)

    # put last func into cu_func_info
    func.argc = len(func.args_name)
    cu_func_info.append(func)
    cu_func_info_dict[func.start] = func
    if trace: print(func)

    if debug: print_str_list(cu_func_info)
    return cu_func_info, cu_func_info_dict

def get_die_block_text(cu):
    dies = g_die_pattern.findall(cu)
    if dies:
        #print(dies)
        return dies
    return []

def print_str_list(strs):
    for s in strs:
        print(s)

def main():
    all_func_info = []
    all_func_info_dict = {}
    with open("debug_info.txt", 'r') as f:
        txt = f.read()

    cus = get_compilation_uint(txt)
    for cu in cus:
        dies = get_die_block_text(cu)
        func_dies = get_function_dies(dies)
        #print_str_list(func_dies)
        _, cu_func_info = get_cu_func_info(func_dies, debug=False, trace=False)
        all_func_info_dict.update(cu_func_info)

    print("\nall function info: ")
    print_str_list(all_func_info_dict.values())
    pass 

if __name__ == "__main__":
    main()