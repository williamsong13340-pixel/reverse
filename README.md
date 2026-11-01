# reverse

逆向分析记录与工具。

## 报告

| 报告 | 结论 |
|---|---|
| [冰汽时代2 v1.0-v1.6.1 二十六项修改器（风灵月影 FLiNG）](reports/frostpunk2-fling-trainer.md) | 无壳；未发现恶意代码；行为与官方 FLiNG 修改器一致，风险低 |

## 工具（`tools/`）

纯 Python 静态分析脚本，依赖 `pefile capstone dnfile dncil unicorn`（`pip install pefile capstone dnfile dncil unicorn`）。

| 脚本 | 用途 |
|---|---|
| `pe_overview.py <pe>` | PE 概览：节表与熵、导入表、TLS、调试信息、Rich 头、版本信息 |
| `pe_resources.py <pe> <outdir>` | 导出全部资源，并显示大小、熵和文件头魔数 |
| `strings_by_section.py <pe> [minlen] [sections]` | 按节提取 ASCII 和 UTF-16（含中文）字符串 |
| `dotnet_meta.py <asm>` | .NET 元数据：程序集引用、P/Invoke、类型和成员引用、用户字符串 |
| `il_dump.py <asm>` | 反汇编全部方法的 IL，并解析 token |
| `xref.py <pe> <db.pkl>` / `q.py <db.pkl> imp\|str\|fn\|callers <arg>` | 基于 `.pdata` 的 x64 交叉引用库及查询 |
| `disasm_pe.py <pe> <start> <end>` | 带导入表和字符串注释的反汇编 |
| `emu.py <pe> <funcs> [maxinsn] [rcx_global]` | 用 Unicorn 模拟指定函数（所有 API 均为桩函数），记录动态解析的 API |
| `strdecrypt.py <pe> <key>` | 还原 MINSTD-XOR 编译期加密的字符串 |

分析样本时请放在单独的目录里，用 `python3 -I` 运行脚本，**不要把样本提交进仓库**（`.gitignore` 已排除常见二进制格式）。
