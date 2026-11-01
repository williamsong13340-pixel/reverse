# 《冰汽时代2》v1.0-v1.6.1 二十六项修改器（风灵月影 / FLiNG）逆向安全分析报告

> 分析日期：2026-11-01　·　方法：静态逆向 + 局部指令模拟（Unicorn）　·　**样本全程未在真实系统上运行**

## 结论速览

**判定：未发现恶意代码。** 样本的结构、代码和资源都与风灵月影（FLiNG）官方修改器框架一致，所有"看起来可疑"的特征都能对应到正常的修改器功能。**风险等级：低，可以运行**（需要管理员权限，建议见第 7 节）。

| 检查项 | 结果 |
|---|---|
| 加壳 | **无**商业壳（不是 UPX / VMProtect / Themida / Enigma），标准 MSVC 编译产物 |
| 混淆 | 两层轻度自制混淆：资源用 32 字节密钥 XOR 加密；敏感 API 名在编译期加密，运行时用 `GetProcAddress` 获取。**均已完全解开** |
| 内嵌程序 | ① .NET WPF 界面（加密存放）② `TrSpeedHack.dll` 变速 DLL ③ 游戏封面 JPEG 和提示音 |
| 联网 | 只有 .NET 界面会联网：检查更新、3DM 广告图、（仅当装了风灵月影 App 时）会员验证。域名只有 `flingtrainer.com` / `3dmgame.com` |
| 下载并执行代码 | **无**。没有 `Assembly.Load`，也没有任何执行下载内容的代码路径 |
| 窃密 / 键盘记录 | **无**。`GetAsyncKeyState` 只用于快捷键；不读取浏览器、Steam、Discord、钱包等任何数据 |
| 持久化 / 自启动 | **无**。不写注册表、不建服务/计划任务、不改启动项 |
| 进程注入 | 有，但**只针对游戏进程** `Frostpunk2-*-Shipping.exe`（改内存 + 注入变速 DLL），是修改器的本职工作 |
| 反调试 / 反虚拟机 / 直接系统调用 | **无** |
| 数字签名 | 无（风灵月影的修改器一贯不签名） |

---

## 1. 样本信息

| 项目 | 值 |
|---|---|
| 文件名 | `Frostpunk 2 v1.0-v1.6.1 Plus 26 Trainer.exe` |
| 大小 | 1,705,984 字节 |
| MD5 | `e3b89ea983973acf3fb4ecbfc170552b` |
| SHA-1 | `11321da99d3898ab5e3d768f3ac30277534d2a7f` |
| SHA-256 | `cd6609da0f0ba99d4a2e81250d2ec3ecd5b2810024b723881cd1221dbb43e786` |
| 类型 | PE32+ x64 GUI 程序 |
| 编译时间 | 2026-07-17 08:06:46 UTC |
| 编译器 | MSVC（链接器 14.51，C++，静态 CRT） |
| 版本信息 | CompanyName = `3DMGAME`，LegalCopyright = `FLiNG Copyright (C) 2026` |
| 权限清单 | `requireAdministrator`（启动时弹出 UAC） |
| 签名 | 无 Authenticode 签名 |

## 2. 查壳

节表全部是 MSVC 标准节名，入口点位于 `.text`，没有附加数据（overlay），TLS 回调表为空：

| 节 | 原始大小 | 熵 | 说明 |
|---|---|---|---|
| `.text` | 0xD2C00 | 6.44 | 正常机器码的熵值（加壳代码一般 > 7.2） |
| `.rdata` | 0x42400 | 5.56 | 常量、字符串、导入表 |
| `.data` | 0x3600 | 3.35 | |
| `.pdata` | 0x8200 | 5.98 | x64 异常表，完整覆盖 2745 个函数（加壳通常会破坏它） |
| `.fptable` | 0x200 | 0.00 | 新版 MSVC 生成 |
| `.rsrc` | 0x7EA00 | **7.55** | 熵偏高 → 里面有加密资源（见第 3 节） |
| `.reloc` | 0x1000 | 5.17 | |

**结论：没有加壳。** 只有两处轻度自制混淆，目的是躲避杀毒软件特征码，而不是隐藏恶意行为：

1. **资源 XOR 加密**：`UI/101`、`COVER/117` 两个资源用 32 字节循环密钥 XOR 加密。密钥在 `sub_14004DC40` 中用栈上立即数拼出：
   `f4d98d41 7607ce83 a8a4dcab ca44b4e0 42f3fe13 b6f1da35 ec10c0cb 34485c07`
2. **API 名编译期加密**：`OpenProcess`、`WriteProcessMemory`、`CreateRemoteThread` 等 21 个 API 名，以 MINSTD（Park–Miller）线性同余流密钥 XOR 的形式存放（种子 `0xF2E62E75`），运行时解密后通过 `GetProcAddress` 获取，因此不出现在导入表里。全部 41 条隐藏字符串都已解出，没有恶意内容（见附录 A）。

## 3. 文件结构

```
Frostpunk 2 ... Trainer.exe     原生 C++ 主程序（修改逻辑、AsmJit 汇编器、虚幻引擎反射解析）
├── 资源 UI/101     (XOR) → FLiNGTrainerGUI_WPF.exe   .NET Framework 4 WPF 界面，216,064 字节
├── 资源 COVER/117  (XOR) → 冰汽时代2 封面 JPEG 330×440（Photoshop 制作，2024-09-19）
├── 资源 REMOTE/250 (明文) → TrSpeedHack.dll  "Trainer Speedhack Library" © FLiNG 2024
├── 资源 WAVE/103,104      → 开启/关闭功能的提示音
└── 图标、版本信息、清单（requireAdministrator）
```

解出的组件哈希（SHA-256）：

| 组件 | SHA-256 |
|---|---|
| FLiNGTrainerGUI_WPF（.NET 界面） | `bbf77ead6a86199b078617d1dd7386107bb738501c07899441bb196db3f7bd87` |
| TrSpeedHack.dll | `be24440e4bd3c07729e931533b9b097df945f57b876c28c0d8e0bbb743645324` |
| 封面 JPEG | `8ca8de7643e2ff42b2df4f5f8cc720fddbc04f631ba5cb55682e6f8c165f17b8` |

## 4. 行为分析

### 4.1 原生主程序

**启动流程**

1. 检测是否运行在 Wine 下（`ntdll!wine_get_version`），必要时带 `-retry-non-windows` 参数重启自身。
2. 解密 `UI` 资源，通过 CLR 宿主接口（`CLRCreateInstance`）在**本进程内**加载 .NET 界面（直接从内存加载，或先写成 `%TEMP%\FLiNGTrainer.tmp` / `%TEMP%\<数字>.tmp` 再加载）。
3. 界面创建命名管道 `\\.\pipe\FLiNGTrainerNamedPipe_<自身PID>`，主程序连接后把语言、功能列表、封面、游戏状态、广告和更新地址等下发给界面。界面通过主程序传入的回调 `ExecuteTrainerCommand` 回传按钮和快捷键命令。

**修改功能**

进程和内存相关的 API 存放在全局 API 表 `0x14011BA20` 中（已用 Unicorn 模拟确认每个地址对应的 API）；`ShellExecuteW` 则在调试日志函数里单独获取。下表的引用次数来自对整个代码段的扫描：

| API | 用途 |
|---|---|
| `CreateToolhelp32Snapshot` / `Process32FirstW/NextW` / `Module32FirstW/NextW` | 查找游戏进程 `Frostpunk2-Win64-Shipping.exe`（Steam/Epic）或 `Frostpunk2-WinGDK-Shipping.exe`（Game Pass）及其模块 |
| `OpenProcess` | 打开游戏进程 |
| `ReadProcessMemory` / `VirtualQueryEx` | 特征码（AOB）扫描 |
| `VirtualAllocEx` / `WriteProcessMemory` / `VirtualProtectEx` / `VirtualFreeEx` | 在游戏里分配代码洞、写入 Hook 代码，退出时释放 |
| `CreateRemoteThread` | **整个程序只有 1 处调用**：用 `LoadLibraryW` 把 TrSpeedHack.dll 注入游戏（变速功能） |
| `GetAsyncKeyState` | 检测快捷键（全程序共 11 处引用，都在快捷键处理里） |
| `OpenProcessToken` / `LookupPrivilegeValueW` / `AdjustTokenPrivileges` / `FindWindowW` | 已解析，但在本版本中**从未被调用**（全程序 0 处引用，属框架残留） |
| `CreateProcessW` | 只用来**重启修改器自身**（切换语言、Wine 重试） |
| `TerminateProcess` | 所有调用的目标都是 `GetCurrentProcess()`，即**只结束修改器自己**，不会结束其他进程 |
| `ShellExecuteW` | 打开调试日志 `debug_log.txt` |

修改逻辑本身是内置的 Cheat Engine 风格自动汇编脚本（`[ENABLE]/[DISABLE]`、`aobscanmodule`、`alloc`、`registersymbol`），由内置的 AsmJit 汇编器实时编译。脚本只针对 `Frostpunk2-Win64-Shipping.exe`，对应资源、人口、派系信任、即时建造、即时研究、即时探索、提案必定通过、议会冷却、发电机零磨损、游戏速度等功能。

**没有发现的东西**：注册表 API（静态和动态都没有）、网络 API、服务/计划任务、直接系统调用（`syscall`）、PEB 遍历式的隐藏 API 获取、反调试/反虚拟机（`cpuid` 只出现在 CRT 的 CPU 特性检测里）。TLS 回调表为空。

### 4.2 .NET 界面（FLiNGTrainerGUI_WPF）

- P/Invoke 只有：`CreateFileMapping` / `OpenFileMapping` / `MapViewOfFile` / `UnmapViewOfFile` / `CloseHandle`（共享内存）、`Get/WritePrivateProfileString`（INI 配置）、`LCMapString`（简繁转换）、`GetAsyncKeyState`（快捷键）。
- 没有 `Assembly.Load`，不会加载额外的 .NET 代码。`Activator.CreateInstance` 和反射只出现在 WPF 自动生成的 `GeneratedInternalTypeHelper` 里。
- 所有 `Process.Start` 都在**按钮点击事件**中：打开更新页、作者支持/求修改器/求更新页面、3DM 广告链接、WeMod 推广链接、启动 Game Pass 版游戏 exe（路径由你自己设置）。
- 内嵌资源只有 WPF 界面布局（BAML）和一张 `wemod.jpg` 推广图。

**联网行为（只有这三处）**

| 功能 | 请求 | 发出的数据 | 下载内容的用途 |
|---|---|---|---|
| 检查更新 | GET `https://flingtrainer.com/wp-content/check-for-trainer-update/` + 修改器标识 | 修改器标识（URL 的一部分） | 只当作版本号字符串比较，有新版就显示"检测到新版本"文字。**不会自动下载或运行任何东西** |
| 3DM 广告横幅 | GET `https://www.3dmgame.com/flxgq.html`，再下载其中的图片 | 无 | 解析出 `<a href>` 和 `<img src>`，图片只用于显示；点击广告才会用浏览器打开链接 |
| 风灵月影 App 会员验证 | POST `https://flingtrainer.com/cn/community/api/v2/app-login.php` | `user_name`、`password` | 返回 `login-ok` 就隐藏广告 |

关于会员验证：**只有当你安装过风灵月影官方的"修改器合集 App"并保存了登录信息**（`%LOCALAPPDATA%\FLiNGTrainer_App\settings.json` 中有 `saved_user_name` / `saved_password`）时才会发生，账号密码只发给风灵月影自己的服务器。如果 App 正在运行，则改为读取 App 的共享内存 `FLiNGTrainer_App_Instance_M` 做 SHA-256 校验，不联网。没装 App 的用户不会有任何账号数据外发。

所有请求的 User-Agent 都是 `FLiNGTrainer`。一个小瑕疵：程序把 TLS 协议设为 `SSL3 | TLS1.0`（`ServicePointManager.SecurityProtocol = 240`），协议偏旧，属于安全性不佳，不是恶意行为。

### 4.3 TrSpeedHack.dll（变速 DLL）

- 只在你开启"游戏速度"功能时，才会释放到 `%TEMP%\FLiNGTrainerTemp\` 并注入游戏。
- 功能：Hook `GetTickCount`、`timeGetTime`、`QueryPerformanceCounter`、`RtlQueryPerformanceCounter`，按倍率缩放时间（与 CE 变速原理相同）。导入表与 MinHook 吻合（挂起线程、修正线程上下文）。
- 没有网络操作，除 CRT 自带的以外没有文件操作，也没有可疑字符串。
- 为了让 Game Pass（UWP 沙盒）版游戏能加载这个 DLL，主程序会给**这一个 DLL 文件**加上"ALL APPLICATION PACKAGES"（`S-1-15-2-1`）的**读取 + 执行**权限（`GENERIC_READ | GENERIC_EXECUTE = 0xA0000000`），不影响其他任何文件。

### 4.4 "安装反作弊绕过"按钮

界面框架中有这个按钮（多款游戏通用），但在本修改器里，负责执行它的 `std::function` 回调（全局变量 `0x14011C330`）**从来没有被赋值**。命令到达时检测到回调为空就直接跳过。**这个功能在本版本中处于休眠状态，不会改动任何游戏文件。** 检测到反作弊时，修改器只会弹窗提示"请按照说明文件（readme.txt）中的步骤运行游戏"。

## 5. 会在你电脑上产生的文件

| 位置 | 内容 |
|---|---|
| `%LOCALAPPDATA%\FLiNGTrainer\` | `TrainerSettings.ini`、`trainer-settings\*.ini`（含 `GamePassExePath` 等）、`trainer-logs\`（`info.ini`、`locations.txt`）、`version\`、`symbols.ini`、`Profiles\` 等 |
| `%TEMP%\FLiNGTrainer.tmp` 或 `%TEMP%\<数字>.tmp` | 解密后的 .NET 界面程序 |
| `%TEMP%\FLiNGTrainerTemp\TrSpeedHack*.dll` | 变速 DLL（仅在使用变速功能时） |
| `debug_log.txt` | 调试日志（仅在调试时） |

不写注册表，不修改系统文件，也不修改游戏文件。

## 6. 网络连接清单

- `flingtrainer.com`：更新检查、会员验证，以及各种点击后打开的页面
- `www.3dmgame.com`：广告页；`bbs.3dmgame.com`：修改器发布帖链接（点击后打开）
- 广告图片所在的服务器（由 3DM 广告页决定）

没有发现 IP 直连、可疑域名，也没有 Pastebin / Discord / Telegram 之类的数据回传渠道。

## 7. 风险评估与建议

**为什么杀毒软件可能会报毒**：读写其他进程的内存、用 `CreateRemoteThread` 注入 DLL、加密 API 名、加密资源、从内存加载 .NET 程序，这些都是杀软启发式规则的典型触发点。几乎所有修改器都会被报为 HackTool / Trainer / PUA 一类，这不等于病毒。

**建议**

1. **确认来源**：最好从 flingtrainer.com 或 3DM 官方渠道下载，并核对 SHA-256 是否与本报告一致（也可以把哈希粘贴到 VirusTotal 搜索）。本次分析只能证明"这个文件"的行为，不能替别处下载的同名文件担保。
2. **运行前备份存档**：修改内存可能导致游戏崩溃或存档异常。这是修改器的固有风险，不是安全问题。
3. 修改器的清单强制要求管理员权限，只对你信任并核对过哈希的文件点"是"。
4. 不想让它联网的话，可以用 Windows 防火墙禁止这个 exe 出站。修改功能不依赖网络，只是没有更新提示和广告。
5. 不点界面里的广告横幅，可以规避第三方广告内容带来的风险。
6. 冰汽时代2 是单机游戏，没有封号风险；不要把修改器用在有反作弊的联网游戏上。
7. 用完想清理的话，删除 `%TEMP%\FLiNGTrainerTemp`、`%TEMP%\FLiNGTrainer.tmp` 和 `%LOCALAPPDATA%\FLiNGTrainer` 即可。

## 8. 分析方法与局限

- 全程在 Linux 隔离环境中做静态分析，样本**没有被执行**（环境里也没有 Wine）。
- 工具：pefile、capstone（反汇编与交叉引用）、dnfile + dncil（.NET 元数据与 IL 反汇编）、Unicorn（只模拟了两个 API 解析函数，所有 Windows API 都换成了桩函数）。脚本在仓库的 `tools/` 目录下。
- 局限：静态分析无法覆盖服务器端将来的变化（例如广告图片和链接内容），但代码里不存在执行下载内容的路径。另外，没有与官方原版文件做逐字节比对。

---

## 附录 A：解出的 41 条隐藏字符串

| 类别 | 内容 |
|---|---|
| 模块（4） | `Kernel32.dll`、`Advapi32.dll`、`User32.dll`、`Shell32.dll` |
| API（21） | `OpenProcess`、`CreateToolhelp32Snapshot`、`Process32NextW`、`Module32FirstW`、`Module32NextW`、`K32GetProcessMemoryInfo`、`CreateProcessW`、`TerminateProcess`、`OpenProcessToken`、`LookupPrivilegeValueW`、`AdjustTokenPrivileges`、`ReadProcessMemory`、`WriteProcessMemory`、`CreateRemoteThread`、`VirtualAllocEx`、`VirtualFreeEx`、`VirtualQueryEx`、`VirtualProtectEx`、`FindWindowW`、`GetAsyncKeyState`、`ShellExecuteW`（`Process32FirstW` 为明文） |
| 内部命令（10） | `FLiNGTrainerNamedPipe_`、`TRAINER_INITIALIZE`、`CUSTOM_INIT_MESSAGE`、`SET_GAMEPASS_EXE_PATH`、`ENABLE_ANTICHEAT_BYPASS`、`CHECK_UPDATE`、`SET_COMBOBOX_ITEMS`、`WMURL`、`{CMD}_SetLanguage`、`{CMD}_InstallAnticheatBypass` |
| URL（6 段） | `https://flingtrainer.com/wp-content/check-for-trainer-update/`、`https://flingtrainer.com/download-wemod-trainer.php?name=`、`https://flingtrainer.com/cn/2.html`、`https://flingtrainer.com/tag/`、`https://bbs.3dmgame.com/thread-` + `-1-1.html` |

## 附录 B：关键证据（节选）

资源解密，`sub_14004DC40`：

```asm
mov   dword ptr [rbp-0x20], 0x418dd9f4    ; key = f4 d9 8d 41 76 07 ce 83 ...
mov   dword ptr [rbp-0x1c], 0x83ce0776
...
and   eax, 0x1f
movzx r13d, byte ptr [rbp + rax - 0x20]   ; key[i & 31]
xor   r13b, byte ptr [r12 + rcx]          ; ^ data[i]
```

字符串解密，`sub_1400339E0` 等：`s = 0xF2E62E75; out[i] = in[i] ^ (s & 0xFF); s = (s * 48271 mod 2^32) mod (2^31 - 1)`

反作弊绕过处于休眠，`sub_14003DA50`（`0x14011C368` 是 `std::function` 的内部指针，全程序没有任何写入）：

```asm
mov   rcx, qword ptr [0x14011C368]
test  rcx, rcx
je    skip                ; 回调为空，直接跳过
mov   rax, [rcx]
call  qword ptr [rax+0x10]
```

`TerminateProcess` 只结束自身，`sub_1400368F0` / `sub_14003BFD0`：

```asm
mov   rbx, qword ptr [0x14011BAA8]   ; TerminateProcess
call  GetCurrentProcess
mov   rcx, rax                        ; 目标 = 修改器自己
xor   edx, edx
call  rbx
```

会员验证，.NET IL `MainWindow::<CheckSettings>b__147_0`：

```
ldstr "user_name"  ; ldfld AppSettings::saved_user_name   （来自 FLiNGTrainer_App\settings.json）
ldstr "password"   ; ldfld AppSettings::saved_password
ldstr "https://flingtrainer.com/cn/community/api/v2/app-login.php"
call  Utils::PostRequest
```
