---
title: "Memory Forensics"
date: 2025-06-19
---

-----

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

4.  **对转储的 Hive 执行快速 `regripper` 分析
