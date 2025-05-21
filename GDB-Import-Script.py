import gdb
import argparse
import pwndbg.commands
import subprocess
import os

try:
    import pwndbg.gdblib.symbol as symbol
    import pwndbg.gdblib.proc as proc
    import pwndbg.gdblib.elf as elf
except ImportError:
    import pwndbg.symbol as symbol
    import pwndbg.proc as proc
    import pwndbg.elf as elf

#用来缓存pie地址与pie是否开启，无需每次都调用命令
pie_addr : int|None = None
is_pie_enabled : bool|None = None

# 存储用户的符号和断点
user_symbols = {}
user_breakpoints = {}

# 保存原始的symbol.get方法
original_symbol_get = symbol.get

# 文件路径
SAVE_FILE = '.rename'
BREAKPOINT_FILE = '.rename_breakpoints'

# 重新定义获取符号的方法，支持偏移显示
def renamed_symbol_get(address, *a, **kw):
    if address in user_symbols:
        name = user_symbols[address]
        if '+' in name:
            function_name, offset = name.split('+')
            return f"{function_name}+{offset}"  # 显示函数名和偏移
        return name  # 如果没有偏移，返回原符号名
    return original_symbol_get(address, *a, **kw)

# 安装和卸载符号钩子
def install_hook():
    symbol.get = renamed_symbol_get

def uninstall_hook():
    symbol.get = original_symbol_get
    user_symbols.clear()
    user_breakpoints.clear()

# 检查是否为PIE（位置无关执行文件）
def is_pie():
    global is_pie_enabled
    if is_pie_enabled != None:
        return is_pie_enabled
    try:
        result = subprocess.run(['checksec', '--fortify-file', '--pie'], capture_output=True, text=True)
        if "No PIE" not in result.stdout:
            is_pie_enabled = True
            return True
    except FileNotFoundError:
        print("[!] checksec not found, cannot verify PIE status.")
    is_pie_enabled = False
    return False

# 获取PIE基址
def get_pie_base():
    global pie_addr
    if is_pie():
        if pie_addr != None:
            return pie_addr
        try:
            result = gdb.execute('piebase', to_string=True).strip()
            if result:
                import re
                match = re.search(r'0x[0-9a-fA-F]+', result)
                if match:
                    pie_base = match.group(0)
                    pie_addr = int(pie_base, 16)
                    return pie_addr
                else:
                    print("[!] Error: Unable to extract PIE base address from the output.")
                    return 0
            else:
                print("[!] Error: Unable to retrieve PIE base address.")
                return 0
        except gdb.error:
            print("[!] Error: Unable to retrieve PIE base address.")
            return 0
    return 0

# 修复地址（考虑PIE基址）
def fix_address(addr):
    pie_base = get_pie_base()
    if pie_base:
        if addr >= pie_base:
            return addr
        else:
            return addr + pie_base

# 获取绝对地址
def get_absolute_address(addr):
    pie_base = get_pie_base()
    if pie_base:
        if addr >= pie_base:
            return addr
        else:
            return addr + pie_base

# 解析符号文件并生成符号列表
def parse_symbol_file(path):
    symbols = []
    with open(path, 'r') as f:
        for line in f:
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            start = fix_address(int(parts[0], 16))
            end = fix_address(int(parts[1], 16))
            name = parts[2]
            size = end - start
            symbols.append((name, start, size))
    return symbols

# 导入符号并显示带偏移的符号
@pwndbg.commands.Command
def rename_import(file):
    try:
        with open(file, 'r') as f:
            for line in f:
                if not line.strip() or line.startswith("#"):
                    continue
                parts = line.strip().split()
                if len(parts) < 2:
                    print(f'[!] Invalid line: {line.strip()}')
                    continue
                if len(parts) >= 3:
                    start_str, end_str, name = parts[0], parts[1], parts[2]
                    start = fix_address(int(start_str, 0))
                    end = fix_address(int(end_str, 0))
                    for a in range(start, end):
                        user_symbols[a] = f"{name}+{a - start}" # 10 进制显示方法
                        # user_symbols[a] = f"{name}+0x{a - start :x}" # 16进制显示方法
                    user_symbols[start] = name
                    print(f"✓ imported {name} ({start:#x} - {end:#x})")
                elif len(parts) == 2:
                    addr_str, name = parts[0], parts[1]
                    addr = fix_address(int(addr_str, 0))
                    user_symbols[addr] = name
                    print(f"✓ imported {name} at {addr:#x}")
                else:
                    print(f"[!] Invalid line format: {line}")
                # 设置断点
                if len(parts) > 2 and parts[2] == '#bp':
                    abs_addr = get_absolute_address(addr)
                    gdb.execute(f'b *{hex(abs_addr)}')
                    user_breakpoints[addr] = name
                    print(f'✓ Breakpoint set at {name} (address 0x{abs_addr:x})')
    except Exception as e:
        print(f'[!] Failed to import: {e}')

# 保存符号重命名
@pwndbg.commands.Command
def rename_save():
    try:
        with open(SAVE_FILE, 'w') as f:
            for addr, name in user_symbols.items():
                f.write(f'0x{addr:x} {name}\n')
        print(f'✓ Saved to {SAVE_FILE}')
    except Exception as e:
        print(f'[!] Failed to save: {e}')

# 加载符号重命名
@pwndbg.commands.Command
def rename_load():
    if not os.path.exists(SAVE_FILE):
        print(f'[!] {SAVE_FILE} not found')
        return
    rename_import(SAVE_FILE)

# 显示重命名的符号
@pwndbg.commands.Command
def rename_list():
    if not user_symbols:
        print('No renamed symbols.')
    for addr, name in sorted(user_symbols.items()):
        breakpoint_status = 'with breakpoint' if addr in user_breakpoints else 'no breakpoint'
        print(f'0x{addr:x}: {name} ({breakpoint_status})')

# 删除符号重命名
@pwndbg.commands.Command
def rename_delete(addr):
    try:
        addr = int(addr, 0)
        addr = fix_address(addr)
        if addr in user_symbols:
            del user_symbols[addr]
            if addr in user_breakpoints:
                gdb.execute(f'clear {user_breakpoints[addr]}')
                del user_breakpoints[addr]
            print(f'✓ Deleted rename for 0x{addr:x}')
        else:
            print(f'[!] No rename for 0x{addr:x}')
    except Exception as e:
        print(f'[!] Failed to delete: {e}')

# 卸载钩子
@pwndbg.commands.Command
def rename_uninstall():
    uninstall_hook()
    print('Rename hooks uninstalled.')

# 安装符号钩子
install_hook()
