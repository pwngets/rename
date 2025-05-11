**讲解视频：【gdb插件rename讲解】https://www.bilibili.com/video/BV1eQVAzHERg?vd_source=ed440e32ae7ae7faab7b9a2b3236e338**

修改自 _gets佬的 rename插件，实现了在gdb中的 **func_name + offset** 的显示 (现在以十进制显示，与pwndbg显示方式一致)

如果要十六进制的显示，可以前往 HexShow分支下载.

膜拜_gets佬,从小看gets佬wp长大的(bushi

Orz

# 下载方法

找到你想要放置插件的位置，运行

```sh
git clone https://github.com/MindednessKind/rename.git
```

或者在Release中分开下载



IDA-Outport-Script.py 是IDA用来导出函数表的脚本

GDB-Import-Script.py 是GDB用来导入函数表的脚本



# 使用方法

## IDA

IDA反编译时重命名函数。选择 File->ScriptFile， 导入 IDA-Outport-Script.py ，如果对导出结果自动放至二进制文件旁不满意，可以对 IDA-Outport-Script.py 的 DEFAULT_OUTPUT_PATH 进行修改。

## GDB



使用gdb时

在使用前

```shell
gdb_plugin_addr = '' #这里写你自己的插件安装位置，也可以删掉这行，将插件安装位置直接填至source后面
source {gdb_plugin_addr}/rename/GDB-Import-Script.py

rename_import ./.rename
```





# 实现结果

![Show](/images/Show.png)

测试环境: Ubuntu 24



代码实现：pwngets

README Edit: 念落