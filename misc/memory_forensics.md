---
title: "Memory Forensics"
date: 2025-06-19
---

## OtterCTF 2018 — 内存取证分析报告

## Reference

[[hsb] Presents: OtterCTF 2018 — Memory Forensics Write-Up](https://monliclican.medium.com/hsb-presents-otterctf-2018-memory-forensics-write-up-c3b9e372c36c)

### 准备工作

在对内存镜像进行分析之前，通常会执行以下常规步骤以获取必要的前期数据：

**步骤 0：准备**

1.  **使用 `imageinfo` 确定内存镜像的建议配置文件**

    通过运行 `volatility imageinfo -f OtterCTF.vmem` 命令，我们可以识别 `volatility` 工具建议的配置文件。在此次分析中，我们选择使用首个建议的配置文件：`Win7SP1x64`。

    因此，后续所有 `volatility` 命令均需包含 `--profile=Win7SP1x64` 配置文件标志。

2.  **列出可用的注册表 Hive**

    此任务通过执行 `volatility` 命令并结合 `hivelist` 插件即可轻松完成：

    ```bash
    volatility -f OtterCTF.vmem --profile=Win7SP1x64 hivelist
    ```

    请务必记录下注册表 Hive 的**虚拟地址**，这些地址将在下一步骤中使用。

3.  **转储可用的注册表 Hive（用于系统分析/凭据转储）**

    利用 `dumpregistry` 命令可便捷地执行此任务。执行以下命令可将注册表 Hive 转储至指定输出目录：

    ```bash
    volatility -f OtterCTF.vmem --profile=Win7SP1x64 dumpregistry -o <Hive虚拟内存地址> -D <输出目录>
    ```

4.  **对转储的 Hive 执行快速 `regripper` 分析**

    执行以下命令可对指定 Hive 文件进行 `regripper` 快速分析：

    ```bash
    rip -r <注册表文件> -f <sam/security/software/system> > <输出文件>
    ```

    上述前期操作有助于确保在正式分析之前，已获取执行快速而全面内存镜像分析所需的初步数据。

-----

### 分析过程

#### 1 — 密码何在？

根据直觉，我们首先使用 `hashdump` 插件列出内存镜像中存储的 NTLM 哈希：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 hashdump
```

然而，Rick 密码对应的 NTLM 哈希值 `518172d012f97d3a8fcc089615283940` 经在线 NTLM 解密工具尝试，未能得到明文密码。

唯一的希望在于密码是否被错误放置（例如，存储在文本文件、配置文件等中），以及——考虑到这是一个 Windows 7 内存镜像——密码是否存储在机器的 LSA secrets 中。

经验证，运行 `volatility` 并结合 `lsadump` 插件，结果如下所示：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 lsadump
```

**FLAG:** `CTF{MortyIsReallyAnOtter}`

-----

#### 2 — 一般信息

为获取系统 IP 地址，可利用 `volatility` 的 `netscan` 插件检查本地地址：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 netscan
```

由于我们已对注册表 Hive 执行 `regripper` 分析，可检查 `compname` 插件下所列的主机名：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 printkey -K "ControlSet001\Control\ComputerName\ComputerName"
```

**FLAG 1:** `CTF{192.168.202.131}`
**FLAG 2:** `CTF{WIN-LO6FAF3DTFE}`

-----

#### 3 — 娱乐时间

根据前一问题中 `netscan` 的输出，我们可以观察到一个名为 `LunarMS.exe` 的运行进程：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 netscan
```

通过快速的 Google 搜索可知，这是一个 MapleStory 服务器。因此：

**FLAG 1:** `CTF{LunarMS}`
**FLAG 2:** `CTF{77.102.199.102}`

-----

#### 4 — 命名游戏

对于此问题，我们的分析重心在于 `LunarMS.exe` 进程的内存驻留页面。此前执行的 `netscan` 命令已提供了 `LunarMS.exe` 进程的进程 ID（PID 708）。借此，我们现在可以使用 `memdump` 插件转储其内存驻留页面：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 memdump -p 708 -D .
```

随后，我们可以使用以下命令搜索与问题相关的字符串：

```bash
strings 708.dmp | grep -a Lunar-3 -C 5
```

第二个结果下方的字符串引起了我们的注意，因此：

**FLAG:** `CTF{0tt3r8r33z3}`

-----

#### 5 — 命名游戏 2

此问题相对简单，我使用常用的十六进制编辑器 `010Editor` 打开了 `LunarMS.exe` 进程的转储文件，并搜索了最后 4 字节（5A 0C 00 00）：

**FLAG:** `CTF{M0rtyL0L}`

-----

#### 6 — 愚蠢的 Rick

挑战题目提供了解决此问题的关键线索。鉴于 Rick 总是通过“复制粘贴”的方式输入密码，我们很有可能通过 `clipboard` 插件获取该密码：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 clipboard
```

**FLAG:** `CTF{M@il_Pr0vid0rs}`

-----

#### 7 — 捉迷藏

通过对内存镜像运行 `pslist` 命令，我们可以观察到以下值得关注的进程：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 pslist
```

当前存在两个可疑进程：

  * `Rick and Morty season 1 download.exe`
  * `vmware-tray.exe`

为何 `vmware-tray.exe` 可疑？因为观察其 **PPID** (父进程 ID)，它是由 PID 3820——即 `Rick and Morty season 1 download.exe`——启动的。为进一步支持此分析，我们可以运行 `cmdline` 命令：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 cmdline -p 3820
volatility -f OtterCTF.vmem --profile=Win7SP1x64 cmdline -p <vmware-tray.exe的PID>
```

此结果显示 `vmware-tray.exe` 进程在一个未知/可疑路径（例如 Temp 目录）下运行。因此：

**FLAG:** `CTF{vmware-tray.exe}`

这表明 Rick 的系统可能已通过恶意种子文件感染了恶意软件。

-----

#### 8 — 荣耀之路

既然已有迹象表明此恶意软件来源于种子文件，我们需要利用 `filescan` 插件在内存镜像中定位该种子文件：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 filescan | grep ".torrent"
```

使用 `dumpfiles` 插件转储该文件并显示其信息，结果如下：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 dumpfiles -Q <torrent文件的虚拟地址> -D .
```

**FLAG:** `CTF{M3an_T0rren7_4_R!ck}`

这进一步支持了我们的假设，即 Rick 的系统是通过恶意种子文件感染的。但具体是如何发生的呢？

-----

#### 9 — 荣耀之路 2

针对此问题，我推断该文件是从某个地方下载的，因此我通过 Google Chrome 浏览器历史记录查看了 Rick 的浏览活动。用户的历史记录通常位于：`C:\Users\<用户名>\AppData\Local\Google\Chrome\User Data\Default\History`。

我们可以使用 `filescan` 插件定位该文件：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 filescan | grep "History"
```

使用 `dumpfiles` 提取文件，并使用 `sqlitebrowser` 查看，结果如下：

为确定 `.torrent` 文件的下载来源，我们必须查看 `site_url`：

```sql
SELECT url FROM downloads ORDER BY start_time DESC LIMIT 1;
```

我们可以看到下载是由“mail.com”引荐的。这意味着恶意软件通过电子邮件中的恶意附件进入了系统。然而，我们仍未获取 Rick 用于登录其电子邮件账户的凭据。或者我们已经得到了？

为提取与电子邮件相关的工件，我使用了 **`bulk_extractor`** 工具。显示其生成的 `email.txt` 内容并使用 `grep` 搜索“@mail.com”，结果显示以下条目：

```bash
bulk_extractor -o output_dir OtterCTF.vmem
grep "@mail.com" output_dir/email.txt
```

我们可以看到 `rickopicko@gmail.com` 存在。如果回顾之前的问题，我们已经获取了 Rick 的电子邮件密码，这归功于 `clipboard` 插件（`M@il_Pr0vid0rs`）。

我们现在可以登录 Rick 的电子邮件账户了！

**FLAG:** `CTF{Hum@n_I5_Th3_Weak3s7_Link_In_Th3_Ch@in}`

-----

#### 10 — Bit 4 Bit

此问题可通过对进程 3720 的转储可执行文件（使用 `procdump` 提取）执行 `strings` 命令，并设置小端序标志来解决：

```bash
volatility -f OtterCTF.vmem --profile=Win7SP1x64 procdump -p 3720 -D .
strings -eL 3720.dmp
```

**FLAG:** `CTF{1MmpEmebJkqXG8nQv4cjJSmxZQFVmFo63M}`

-----

#### 11 — 弱者的图形

我通过对进程 3720 的转储可执行文件使用 `foremost` 工具解决了此问题。它将提取出一个 `.png` 文件：

```bash
foremost -i 3720.dmp
```

**FLAG:** `CTF{S0_Just_M0v3_Socy}`

-----

#### 12 — 恢复

在恶意软件进程的内存转储上执行 `strings` 命令并设置小端序标志，将显示以下内容：

```bash
strings -eL <恶意软件进程内存转储文件>
```

请注意高亮显示的字符串。

乍看之下，该字符串似乎无害，但当您观察其周围的字符串时，会发现它出现在计算机主机名旁边、加密文件（例如 Flag.txt）之后，以及勒索软件常见目标（例如 `.txt`、`.doc`、`.xlsx` 等）之前，这非常不寻常。因此：

**FLAG:** `CTF{aDOBofVYUNVnmp7}`

-----

#### 13 — 总结

如果查看恶意软件中存在的以下指示：

1.  `VapeHacksLoader.exe`
2.  

这些线索将指向 **`$ucyLocker`**，一个基于 **HiddenTear** 的恶意软件。

为解密文件（Flag.txt — 位于 Rick 的桌面），我使用了此工具：`HiddenTear Decrypter`。

然而，在文件能够被解密之前，需要对其本身进行一些更改。首先，我们需要添加 `.WINDOWS` 文件扩展名。此外，我们还需要移除末尾的 NULL 位。

完成上述操作后，提供密码即可解密文件：

完成！

**FLAG:** `CTF{Im_Th@_B3S7_RicK_0f_Th3m_4ll}`

-----

感谢阅读！
