import gdb
import argparse
import pwndbg.commands
import subprocess

try:
    import pwndbg.gdblib.symbol as symbol
    import pwndbg.gdblib.proc as proc
    import pwndbg.gdblib.elf as elf
except ImportError:
    import pwndbg.symbol as symbol
    import pwndbg.proc as proc
    import pwndbg.elf as elf

import os

user_symbols = {}
user_breakpoints = {}

original_symbol_get = symbol.get

SAVE_FILE = '.rename.txt'
BREAKPOINT_FILE = '.rename_breakpoints.txt'

def renamed_symbol_get(address, *a, **kw):
    if address in user_symbols:
        return user_symbols[address]
    return original_symbol_get(address, *a, **kw)

def install_hook():
    symbol.get = renamed_symbol_get

def uninstall_hook():
    symbol.get = original_symbol_get
    user_symbols.clear()
    user_breakpoints.clear()

def is_pie():
    try:
        result = subprocess.run(['checksec', '--fortify-file', '--pie'], capture_output=True, text=True)
        if "No PIE" not in result.stdout:
            return True
    except FileNotFoundError:
        print("[!] checksec not found, cannot verify PIE status.")
    return False

def get_pie_base():
    if is_pie():
        try:
            result = gdb.execute('piebase', to_string=True).strip()
            if result:
                import re
                match = re.search(r'0x[0-9a-fA-F]+', result)
                if match:
                    pie_base = match.group(0)
                    return int(pie_base, 16)
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

def fix_address(addr):
    pie_base = get_pie_base()
    if pie_base:
        if addr >= pie_base:
            return addr
        else:
            return addr+pie_base

def get_absolute_address(addr):
    pie_base = get_pie_base()
    if pie_base:
        if addr >= pie_base:
            return addr
        else:
            return addr+pie_base

parser = argparse.ArgumentParser(description='Rename an address to a function name.')
parser.add_argument('address', type=str, help='Address (e.g., 0x401000 or 0x1234)')
parser.add_argument('name', type=str, help='New function name')
parser.add_argument('-b', '--breakpoint', action='store_true', help='Set breakpoint after renaming')

@pwndbg.commands.ArgparsedCommand(parser)
def rename(address, name, breakpoint):
    try:
        addr = int(address, 0)
        adjusted_addr = fix_address(addr)
        user_symbols[adjusted_addr] = name
        print(f'✓ Renamed 0x{adjusted_addr:x} -> {name}')
        if breakpoint:
            gdb.execute(f'b *{hex(adjusted_addr)}')
            user_breakpoints[adjusted_addr] = name
            print(f'✓ Breakpoint set at {name} (address 0x{adjusted_addr:x})')
    except Exception as e:
        print(f'[!] Failed to rename: {e}')
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
                addr_str, name = parts[0], parts[1]
                addr = int(addr_str, 0)
                addr = fix_address(addr) 
                user_symbols[addr] = name
                print(f'✓ Imported: 0x{addr:x} -> {name}')
                if len(parts) > 2 and parts[2] == '#bp':
                    abs_addr = get_absolute_address(addr)
                    gdb.execute(f'b *{hex(abs_addr)}')
                    user_breakpoints[addr] = name
                    print(f'✓ Breakpoint set at {name} (address 0x{abs_addr:x})')
    except Exception as e:
        print(f'[!] Failed to import: {e}')

@pwndbg.commands.Command
def rename_save():
    try:
        with open(SAVE_FILE, 'w') as f:
            for addr, name in user_symbols.items():
                f.write(f'0x{addr:x} {name}\n')
        print(f'✓ Saved to {SAVE_FILE}')
    except Exception as e:
        print(f'[!] Failed to save: {e}')
@pwndbg.commands.Command
def rename_load():
    if not os.path.exists(SAVE_FILE):
        print(f'[!] {SAVE_FILE} not found')
        return
    rename_import(SAVE_FILE)
@pwndbg.commands.Command
def rename_list():
    if not user_symbols:
        print('No renamed symbols.')
    for addr, name in sorted(user_symbols.items()):
        breakpoint_status = 'with breakpoint' if addr in user_breakpoints else 'no breakpoint'
        print(f'0x{addr:x}: {name} ({breakpoint_status})')
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
@pwndbg.commands.Command
def rename_uninstall():
    uninstall_hook()
    print('Rename hooks uninstalled.')
install_hook()