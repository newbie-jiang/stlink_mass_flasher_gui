# ST-LINK 批量烧录工具（GUI）

这是一个基于 **STM32CubeProgrammer CLI** 的可视化批量烧录脚本（Python + Tkinter），用于在量产/测试场景中快速枚举多块集成 ST-LINK 的开发板，并对选中的设备一键下载（烧录）固件。

适用于：一次连接多块板子（例如 10~20 块）到带供电 USB Hub，批量烧录 `.hex` / `.bin`。

---

## 主要功能

- **自动枚举 ST-LINK 设备**
  - 调用 `STM32_Programmer_CLI.exe -l`
  - 显示当前连接的 **ST-LINK 数量**
  - 列出每个设备的：
    - ST-LINK SN（序列号）
    - 对应的虚拟串口 **COM 口**
    - ST-LINK FW 版本
    - Access Port Number（AP）

- **设备选择**
  - 支持在列表中 **单选/多选**
  - 支持 **全选 / 取消全选**
  - 你可以只烧录某几个设备，也可以一次烧录全部设备

- **固件选择**
  - 支持选择 `.hex` 或 `.bin`
  - **HEX 文件自带地址**，工具会自动忽略“地址输入框”
  - **BIN 文件需要地址**，默认地址为 `0x08000000`（可修改）

- **一键烧录/下载**
  - 对选中的设备依次执行烧录流程
  - 支持可选：
    - `Verify`（烧录后校验）
    - `Reset after`（烧录完成后复位）

- **日志输出**
  - GUI 下方实时显示每个设备的烧录日志
  - 显示每块板的成功/失败结果，以及最终汇总统计（OK/FAIL）

---

## 环境要求

- Windows 10/11
- Python 3.8+（建议 3.10+）
- 已安装 **STM32CubeProgrammer**
- 命令行可执行：
  ```bat
  STM32_Programmer_CLI.exe -l
  建议使用 带外接电源的 USB Hub（量产连接多块板时更稳定）。

![image-20251223235833694](https://cloud.rocketpi.club/cloud/image-20251223235833694.png)