import os
import re
import threading
import queue
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# 如果你的 CLI 不在 PATH，把它改成绝对路径，例如：
# CLI_EXE_DEFAULT = r"C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe"
CLI_EXE_DEFAULT = "STM32_Programmer_CLI.exe"

def run_cli(args, timeout=None):
    cmd = [CLI_EXE_DEFAULT] + args
    p = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        shell=False
    )
    return p.returncode, p.stdout

def parse_stlink_list(text):
    lines = text.splitlines()

    # ST-LINK probes
    probes = []
    current = None
    probe_re = re.compile(r"^\s*ST-Link Probe\s+(\d+)\s*:", re.IGNORECASE)
    sn_re = re.compile(r"^\s*ST-LINK\s+SN\s*:\s*([0-9A-Fa-f]+)\s*$", re.IGNORECASE)
    fw_re = re.compile(r"^\s*ST-LINK\s+FW\s*:\s*(.+?)\s*$", re.IGNORECASE)
    ap_re = re.compile(r"^\s*Access\s+Port\s+Number\s*:\s*(.+?)\s*$", re.IGNORECASE)

    for ln in lines:
        m = probe_re.match(ln)
        if m:
            if current and current.get("sn"):
                probes.append(current)
            current = {"probe_index": int(m.group(1)), "sn": None, "fw": None, "ap": None, "com": None}
            continue
        if current is not None:
            m = sn_re.match(ln)
            if m:
                current["sn"] = m.group(1)
                continue
            m = fw_re.match(ln)
            if m:
                current["fw"] = m.group(1).strip()
                continue
            m = ap_re.match(ln)
            if m:
                current["ap"] = m.group(1).strip()
                continue
    if current and current.get("sn"):
        probes.append(current)

    # UART mapping SN -> COM
    uart_sn_re = re.compile(r"^\s*ST-LINK\s+SN\s*:\s*([0-9A-Fa-f]+)\s*$", re.IGNORECASE)
    port_re = re.compile(r"^\s*Port\s*:\s*(COM\d+)\s*$", re.IGNORECASE)

    sn_to_com = {}
    pending_sn = None
    for ln in lines:
        m = uart_sn_re.match(ln)
        if m:
            pending_sn = m.group(1)
            continue
        if pending_sn:
            m = port_re.match(ln)
            if m:
                sn_to_com[pending_sn] = m.group(1).upper()
                pending_sn = None

    for p in probes:
        p["com"] = sn_to_com.get(p["sn"])
    return probes

def is_hex_file(path):
    return os.path.splitext(path)[1].lower() == ".hex"

def normalize_hex_addr(s):
    s = (s or "").strip()
    if not s:
        return "0x08000000"
    if re.fullmatch(r"[0-9A-Fa-f]{8}", s):
        return "0x" + s
    if re.fullmatch(r"0x[0-9A-Fa-f]+", s):
        return s
    return s

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ST-LINK 批量烧录工具 (STM32CubeProgrammer CLI)")
        self.geometry("1020x680")
        self.minsize(980, 620)

        self.devices = []
        self.log_queue = queue.Queue()
        self.worker_thread = None
        self.stop_flag = threading.Event()

        self.fw_path_var = tk.StringVar(value="")
        self.addr_var = tk.StringVar(value="0x08000000")
        self.verify_var = tk.BooleanVar(value=True)
        self.reset_var = tk.BooleanVar(value=True)
        self.count_var = tk.StringVar(value="设备数：0")
        self.hint_var = tk.StringVar(value="提示：先在下方列表选中设备（可 Ctrl/Shift 多选），再点“一键烧录/下载”。")

        self._build_ui()
        self._poll_log_queue()
        self.refresh_devices()

    def _build_ui(self):
        # Top controls (use grid so buttons won't disappear when window is narrow)
        top = ttk.Frame(self, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)

        # Row 0
        ttk.Button(top, text="刷新设备", command=self.refresh_devices).grid(row=0, column=0, padx=4, pady=2, sticky="w")
        ttk.Button(top, text="全选", command=self.select_all).grid(row=0, column=1, padx=4, pady=2, sticky="w")
        ttk.Button(top, text="取消全选", command=self.select_none).grid(row=0, column=2, padx=4, pady=2, sticky="w")

        ttk.Label(top, textvariable=self.count_var).grid(row=0, column=3, padx=10, pady=2, sticky="w")

        ttk.Checkbutton(top, text="校验 Verify", variable=self.verify_var).grid(row=0, column=4, padx=10, pady=2, sticky="w")
        ttk.Checkbutton(top, text="烧录后复位 Reset", variable=self.reset_var).grid(row=0, column=5, padx=10, pady=2, sticky="w")

        # Row 1
        ttk.Label(top, text="固件文件:").grid(row=1, column=0, padx=4, pady=2, sticky="w")
        ttk.Entry(top, textvariable=self.fw_path_var, width=68).grid(row=1, column=1, columnspan=4, padx=4, pady=2, sticky="we")
        ttk.Button(top, text="选择 HEX/BIN...", command=self.browse_firmware).grid(row=1, column=5, padx=4, pady=2, sticky="e")

        # Row 2
        ttk.Label(top, text="BIN 地址(HEX忽略):").grid(row=2, column=0, padx=4, pady=2, sticky="w")
        ttk.Entry(top, textvariable=self.addr_var, width=16).grid(row=2, column=1, padx=4, pady=2, sticky="w")

        self.flash_btn = ttk.Button(top, text="一键烧录/下载（选中设备）", command=self.flash_selected)
        self.flash_btn.grid(row=2, column=2, padx=8, pady=2, sticky="w")

        self.stop_btn = ttk.Button(top, text="停止", command=self.stop_flashing, state=tk.DISABLED)
        self.stop_btn.grid(row=2, column=3, padx=4, pady=2, sticky="w")

        ttk.Label(top, textvariable=self.hint_var).grid(row=3, column=0, columnspan=6, padx=4, pady=(6,2), sticky="w")

        # allow expanding the firmware entry
        top.grid_columnconfigure(2, weight=1)
        top.grid_columnconfigure(3, weight=1)

        # Middle: device list
        mid = ttk.Frame(self, padding=(8,0,8,8))
        mid.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        columns = ("idx", "com", "sn", "fw", "ap")
        self.tree = ttk.Treeview(mid, columns=columns, show="headings", selectmode="extended", height=14)
        self.tree.heading("idx", text="#")
        self.tree.heading("com", text="COM")
        self.tree.heading("sn", text="ST-LINK SN")
        self.tree.heading("fw", text="FW")
        self.tree.heading("ap", text="AP")

        self.tree.column("idx", width=40, anchor="center")
        self.tree.column("com", width=90, anchor="center")
        self.tree.column("sn", width=320, anchor="w")
        self.tree.column("fw", width=120, anchor="center")
        self.tree.column("ap", width=70, anchor="center")

        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Bottom: log output
        bot = ttk.Frame(self, padding=(8,0,8,8))
        bot.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        ttk.Label(bot, text="日志:").pack(side=tk.TOP, anchor="w")
        self.log_text = tk.Text(bot, height=14, wrap="none")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        log_vsb = ttk.Scrollbar(bot, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)

    def log(self, msg):
        self.log_queue.put(msg)

    def _poll_log_queue(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
        except queue.Empty:
            pass
        self.after(100, self._poll_log_queue)

    def browse_firmware(self):
        path = filedialog.askopenfilename(
            title="选择固件（.hex 或 .bin）",
            filetypes=[
                ("Firmware files", "*.hex *.bin"),
                ("HEX files", "*.hex"),
                ("BIN files", "*.bin"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.fw_path_var.set(path)

    def refresh_devices(self):
        self.tree.delete(*self.tree.get_children())
        self.devices = []

        try:
            rc, out = run_cli(["-l"])
        except FileNotFoundError:
            messagebox.showerror(
                "找不到 CLI",
                f"无法找到：{CLI_EXE_DEFAULT}\n\n"
                "请确认已安装 STM32CubeProgrammer，并且 STM32_Programmer_CLI.exe 在 PATH 中。\n"
                "或把脚本开头的 CLI_EXE_DEFAULT 改为绝对路径。"
            )
            return
        except Exception as e:
            messagebox.showerror("错误", str(e))
            return

        if rc != 0:
            self.log(out)
            messagebox.showwarning("提示", "CLI 返回非 0，详见日志。")
            return

        devs = parse_stlink_list(out)
        self.devices = devs
        self.count_var.set(f"设备数：{len(devs)}")

        for i, d in enumerate(devs, start=1):
            com = d.get("com") or "-"
            sn = d.get("sn") or "-"
            fw = d.get("fw") or "-"
            ap = d.get("ap") or "-"
            self.tree.insert("", tk.END, values=(i, com, sn, fw, ap))

        self.log(f"[刷新] 找到 {len(devs)} 个 ST-LINK 设备。")

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())

    def select_none(self):
        self.tree.selection_remove(self.tree.selection())

    def stop_flashing(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_flag.set()
            self.log("[停止] 已请求停止：会在当前设备烧录完成后停止。")

    def flash_selected(self):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showinfo("忙碌中", "正在烧录中，请先停止或等待完成。")
            return

        fw = self.fw_path_var.get().strip()
        if not fw or not os.path.isfile(fw):
            messagebox.showerror("固件文件", "请先选择有效的固件文件（.hex 或 .bin）。")
            return

        addr = normalize_hex_addr(self.addr_var.get())
        if (not is_hex_file(fw)) and (not re.fullmatch(r"0x[0-9A-Fa-f]+", addr)):
            messagebox.showerror("地址", "BIN 文件需要地址，格式类似 0x08000000。")
            return

        selected = self.tree.selection()
        if not selected:
            messagebox.showerror("未选择设备", "请先在列表里选中至少一个设备（可 Ctrl/Shift 多选），再点“一键烧录/下载”。")
            return

        selected_devs = []
        for item_id in selected:
            vals = self.tree.item(item_id, "values")
            idx = int(vals[0]) - 1
            if 0 <= idx < len(self.devices):
                selected_devs.append(self.devices[idx])

        if not selected_devs:
            messagebox.showerror("选择错误", "选择的行无效，请刷新后重试。")
            return

        self.stop_flag.clear()
        self.flash_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)

        self.worker_thread = threading.Thread(
            target=self._flash_worker,
            args=(selected_devs, fw, addr, self.verify_var.get(), self.reset_var.get()),
            daemon=True
        )
        self.worker_thread.start()

    def _flash_worker(self, devs, fw, addr, verify, do_reset):
        total = len(devs)
        ok = 0
        fail = 0

        self.log("========================================")
        self.log(f"[开始] 选中设备数={total}")
        self.log(f"[固件] {fw}")
        if is_hex_file(fw):
            self.log("[说明] HEX 自带地址，界面地址框将被忽略。")
        else:
            self.log(f"[地址] {addr}")
        self.log("========================================")

        for i, d in enumerate(devs, start=1):
            if self.stop_flag.is_set():
                self.log(f"[停止] 用户停止：在第 {i}/{total} 之前退出。")
                break

            sn = d.get("sn")
            com = d.get("com") or "-"
            self.log(f"\n[{i}/{total}] SN={sn}  COM={com}")

            base = ["-c", "port=SWD", f"sn={sn}", "mode=UR", "reset=HWrst"]

            if is_hex_file(fw):
                w_args = ["-w", fw]
            else:
                w_args = ["-w", fw, addr]

            extra = []
            if verify:
                extra.append("-v")
            if do_reset:
                extra.append("-rst")

            args = base + w_args + extra

            try:
                rc, out = run_cli(args)
            except Exception as e:
                rc = -1
                out = f"[Exception] {e}"

            self.log(out.rstrip())

            if rc == 0:
                ok += 1
                self.log(f"[结果] OK   (OK={ok} / FAIL={fail})")
            else:
                fail += 1
                self.log(f"[结果] FAIL rc={rc} (OK={ok} / FAIL={fail})")

        self.log("\n========================================")
        self.log(f"[完成] OK={ok} FAIL={fail}")
        self.log("========================================")
        self.after(0, self._flash_done_ui)

    def _flash_done_ui(self):
        self.flash_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

if __name__ == "__main__":
    app = App()
    app.mainloop()
