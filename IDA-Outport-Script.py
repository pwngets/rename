import idautils
import idaapi
import idc
import sys

# 默认输出路径，可根据需要修改
DEFAULT_OUTPUT_PATH = r".\.rename"

# 要过滤的前缀列表，如以 'sub' 开头的函数名将被排除
FILTER_PREFIXES = ['sub']

def export_function_list(output_path):
    """
    导出所有函数的起始地址和名称到指定文件，每行格式: 0xADDRESS name
    仅导出函数名不以 FILTER_PREFIXES 列表中前缀开头的函数
    """
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for func_ea in idautils.Functions():
                name = idc.get_func_name(func_ea)
                if not name:
                    continue
                # 排除自动生成的子函数名，如 sub_XXXX
                if any(name.startswith(prefix) for prefix in FILTER_PREFIXES):
                    continue
                f.write(f"0x{func_ea:08X} {name}\n")
        print(f"已导出到: {output_path}")
    except Exception as e:
        print(f"导出失败: {e}")

# 脚本入口
if __name__ == '__main__':
    # 如果通过命令行参数指定路径，则使用之；否则使用默认路径
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    else:
        output_path = DEFAULT_OUTPUT_PATH
    export_function_list(output_path)