import os
import re
import csv
import threading
import queue
import subprocess
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import ttk, filedialog, messagebox

# 如果你的 CLI 不在 PATH，把它改成绝对路径，例如：
# CLI_EXE_DEFAULT = r"C:\Program Files\STMicroelectronics\STM32Cube\STM32CubeProgrammer\bin\STM32_Programmer_CLI.exe"
CLI_EXE_DEFAULT = "STM32_Programmer_CLI.exe"

# STM32F401RE（STM32F4）UID(96-bit) 基地址：0x1FFF7A10，长度 12 字节（3 x 32-bit）
UID_BASE_ADDR = 0x1FFF7A10

# 并发可选项（最高 20 线）
CONCURRENCY_OPTIONS = (1, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20)

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

def parse_uid_from_read_output(out_text: str):
    """
    适配 CubeProgrammer CLI v2.19.0:
      0x1FFF7A10 : 0039001E 35315107 38333932
    返回 24 hex（大写）或 None
    """
    m = re.search(
        r"\b(?:0x)?1FFF7A10\b\s*:\s*([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})\s+([0-9A-Fa-f]{8})",
        out_text
    )
    if m:
        return (m.group(1) + m.group(2) + m.group(3)).upper()

    toks = re.findall(r"\b(?:0x)?([0-9A-Fa-f]{8})\b", out_text)
    toks_u = [t.upper() for t in toks]
    base = "1FFF7A10"
    addr_tokens = {base, "1FFF7A14", "1FFF7A18", "1FFF7A1C"}
    if base in toks_u:
        i = toks_u.index(base) + 1
        words = []
        while i < len(toks_u) and len(words) < 3:
            t = toks_u[i]
            if t not in addr_tokens and re.fullmatch(r"[0-9A-F]{8}", t):
                words.append(t)
            i += 1
        if len(words) == 3:
            return (words[0] + words[1] + words[2]).upper()

    vals = [t for t in toks_u if t not in addr_tokens and re.fullmatch(r"[0-9A-F]{8}", t)]
    if len(vals) >= 3:
        return (vals[0] + vals[1] + vals[2]).upper()

    return None

def read_mcu_uid_via_stlink(sn):
    base = ["-c", "port=SWD", f"sn={sn}", "mode=UR", "reset=HWrst"]
    addr = f"0x{UID_BASE_ADDR:08X}"
    # v2.19.0 输出里会写 "Size : 12 Bytes"，所以这里直接用 12（也兼容 3）
    attempts = [
        ["-r32", addr, "12"],
        ["-r32", addr, "3"],
        ["-r32", addr, "0xC"],
    ]
    last_rc, last_out = 1, ""
    for a in attempts:
        rc, out = run_cli(base + a)
        uid = parse_uid_from_read_output(out)
        if uid:
            return uid, out, rc
        last_rc, last_out = rc, out
    return None, last_out, last_rc

class UidSnTable:
    """只维护一个 uid_sn.csv：两列 uid_96bit_hex, stlink_sn；重复 UID 覆盖为最新。"""
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.data = {}  # uid -> sn
        self._load()
        self._ensure_file_exists()

    def _ensure_file_exists(self):
        os.makedirs(os.path.dirname(self.csv_path), exist_ok=True)
        if not os.path.exists(self.csv_path):
            with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["uid_96bit_hex", "stlink_sn"])

    def _load(self):
        if not os.path.exists(self.csv_path):
            return
        try:
            with open(self.csv_path, "r", newline="", encoding="utf-8") as f:
                r = csv.DictReader(f)
                for row in r:
                    uid = (row.get("uid_96bit_hex") or "").strip().upper()
                    sn = (row.get("stlink_sn") or "").strip()
                    if uid and sn:
                        self.data[uid] = sn
        except Exception:
            self.data = {}

    def upsert_locked(self, uid: str, sn: str, lock: threading.Lock) -> bool:
        uid = (uid or "").strip().upper()
        sn = (sn or "").strip()
        if not uid or not sn:
            return False
        with lock:
            existed = uid in self.data
            self.data[uid] = sn
            self._rewrite_unlocked()
            return existed

    def _rewrite_unlocked(self):
        self._ensure_file_exists()
        with open(self.csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["uid_96bit_hex", "stlink_sn"])
            for uid, sn in self.data.items():
                w.writerow([uid, sn])

def flash_one_device(d, fw, addr, verify, do_reset, record_uid, uid_table, uid_lock, stop_flag, log_fn):
    """
    单设备任务：烧录 + （可选）读 UID + 更新表
    返回 dict:
      {sn, com, flash_ok, uid, uid_written, uid_overwrite, out_flash, out_uid}
    """
    sn = d.get("sn")
    com = d.get("com") or "-"
    result = {
        "sn": sn,
        "com": com,
        "flash_ok": False,
        "uid": "",
        "uid_written": False,
        "uid_overwrite": False,
        "out_flash": "",
        "out_uid": "",
        "uid_rc": None,
        "flash_rc": None,
    }

    if stop_flag.is_set():
        return result

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

    # flash
    try:
        rc, out = run_cli(base + w_args + extra)
    except Exception as e:
        rc = -1
        out = f"[Exception] {e}"
    result["flash_rc"] = rc
    result["out_flash"] = out
    result["flash_ok"] = (rc == 0)

    # uid (optional)
    if record_uid and (not stop_flag.is_set()):
        uid, out_uid, uid_rc = read_mcu_uid_via_stlink(sn)
        result["uid_rc"] = uid_rc
        result["out_uid"] = out_uid
        if uid:
            result["uid"] = uid
            # update table (thread-safe)
            existed = uid_table.upsert_locked(uid, sn, uid_lock)
            result["uid_written"] = True
            result["uid_overwrite"] = existed

    return result

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ST-LINK 批量烧录工具（并行）+ UID/SN 表 (STM32F401RE)")
        self.geometry("1100x760")
        self.minsize(980, 640)

        self.devices = []
        self.log_queue = queue.Queue()
        self.stop_flag = threading.Event()

        self.fw_path_var = tk.StringVar(value="")
        self.addr_var = tk.StringVar(value="0x08000000")
        self.verify_var = tk.BooleanVar(value=True)
        self.reset_var = tk.BooleanVar(value=True)
        self.record_uid_var = tk.BooleanVar(value=True)
        self.conc_var = tk.IntVar(value=4)

        self.count_var = tk.StringVar(value="设备数：0")
        self.hint_var = tk.StringVar(value="提示：先在下方列表选中设备，再点“一键烧录/下载”。并行数越大越快，但对 USB Hub/供电影响更大。")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        log_dir = os.path.join(script_dir, "flash_logs")
        self.table_path = os.path.join(log_dir, "uid_sn.csv")
        self.uid_table = UidSnTable(self.table_path)
        self.uid_lock = threading.Lock()

        self.worker = None  # background coordinator thread

        self._build_ui()
        self._poll_log_queue()
        self.refresh_devices()

    def _build_ui(self):
        top = ttk.Frame(self, padding=8)
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Button(top, text="刷新设备", command=self.refresh_devices).grid(row=0, column=0, padx=4, pady=2, sticky="w")
        ttk.Button(top, text="全选", command=self.select_all).grid(row=0, column=1, padx=4, pady=2, sticky="w")
        ttk.Button(top, text="取消全选", command=self.select_none).grid(row=0, column=2, padx=4, pady=2, sticky="w")

        ttk.Label(top, textvariable=self.count_var).grid(row=0, column=3, padx=10, pady=2, sticky="w")

        ttk.Checkbutton(top, text="校验 Verify", variable=self.verify_var).grid(row=0, column=4, padx=10, pady=2, sticky="w")
        ttk.Checkbutton(top, text="烧录后复位 Reset", variable=self.reset_var).grid(row=0, column=5, padx=10, pady=2, sticky="w")
        ttk.Checkbutton(top, text="记录 UID->SN", variable=self.record_uid_var).grid(row=0, column=6, padx=10, pady=2, sticky="w")

        ttk.Label(top, text="并行数:").grid(row=0, column=7, padx=(18,4), pady=2, sticky="e")
        self.conc_combo = ttk.Combobox(top, values=[str(x) for x in CONCURRENCY_OPTIONS], width=4, state="readonly")
        self.conc_combo.set(str(self.conc_var.get()))
        self.conc_combo.grid(row=0, column=8, padx=4, pady=2, sticky="w")
        self.conc_combo.bind("<<ComboboxSelected>>", lambda e: self.conc_var.set(int(self.conc_combo.get())))

        ttk.Label(top, text="固件文件:").grid(row=1, column=0, padx=4, pady=2, sticky="w")
        ttk.Entry(top, textvariable=self.fw_path_var, width=76).grid(row=1, column=1, columnspan=7, padx=4, pady=2, sticky="we")
        ttk.Button(top, text="选择 HEX/BIN...", command=self.browse_firmware).grid(row=1, column=8, padx=4, pady=2, sticky="e")

        ttk.Label(top, text="BIN 地址(HEX忽略):").grid(row=2, column=0, padx=4, pady=2, sticky="w")
        ttk.Entry(top, textvariable=self.addr_var, width=16).grid(row=2, column=1, padx=4, pady=2, sticky="w")

        self.flash_btn = ttk.Button(top, text="一键烧录/下载（选中设备）", command=self.flash_selected)
        self.flash_btn.grid(row=2, column=2, padx=8, pady=2, sticky="w")

        self.stop_btn = ttk.Button(top, text="停止", command=self.stop_flashing, state=tk.DISABLED)
        self.stop_btn.grid(row=2, column=3, padx=4, pady=2, sticky="w")

        ttk.Label(top, textvariable=self.hint_var).grid(row=3, column=0, columnspan=9, padx=4, pady=(6,2), sticky="w")

        top.grid_columnconfigure(2, weight=1)
        top.grid_columnconfigure(3, weight=1)
        top.grid_columnconfigure(4, weight=0)
        top.grid_columnconfigure(5, weight=0)
        top.grid_columnconfigure(6, weight=0)
        top.grid_columnconfigure(7, weight=0)

        mid = ttk.Frame(self, padding=(8,0,8,8))
        mid.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        columns = ("idx", "com", "sn", "fw", "ap")
        self.tree = ttk.Treeview(mid, columns=columns, show="headings", selectmode="extended", height=14)
        for k, title in [("idx","#"),("com","COM"),("sn","ST-LINK SN"),("fw","FW"),("ap","AP")]:
            self.tree.heading(k, text=title)

        self.tree.column("idx", width=40, anchor="center")
        self.tree.column("com", width=90, anchor="center")
        self.tree.column("sn", width=360, anchor="w")
        self.tree.column("fw", width=120, anchor="center")
        self.tree.column("ap", width=70, anchor="center")

        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        bot = ttk.Frame(self, padding=(8,0,8,8))
        bot.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=True)

        ttk.Label(bot, text="日志:").pack(side=tk.TOP, anchor="w")
        self.log_text = tk.Text(bot, height=17, wrap="none")
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        log_vsb = ttk.Scrollbar(bot, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_vsb.set)
        log_vsb.pack(side=tk.RIGHT, fill=tk.Y)

        self.log(f"[UID/SN 表] {self.table_path}（重复UID会覆盖为最新；文件已存在则会加载）")

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
        self.after(80, self._poll_log_queue)

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
            self.tree.insert("", tk.END, values=(i, d.get("com") or "-", d.get("sn") or "-", d.get("fw") or "-", d.get("ap") or "-"))

        self.log(f"[刷新] 找到 {len(devs)} 个 ST-LINK 设备。")

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())

    def select_none(self):
        self.tree.selection_remove(self.tree.selection())

    def stop_flashing(self):
        if self.worker and self.worker.is_alive():
            self.stop_flag.set()
            self.log("[停止] 已请求停止：将取消未开始的任务；正在烧录的会在结束后停止继续。")

    def flash_selected(self):
        if self.worker and self.worker.is_alive():
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

        conc = int(self.conc_combo.get()) if self.conc_combo.get().isdigit() else self.conc_var.get()
        if conc < 1:
            conc = 1

        self.stop_flag.clear()
        self.flash_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)

        self.worker = threading.Thread(
            target=self._flash_parallel_worker,
            args=(selected_devs, fw, addr, self.verify_var.get(), self.reset_var.get(), self.record_uid_var.get(), conc),
            daemon=True
        )
        self.worker.start()

    def _flash_parallel_worker(self, devs, fw, addr, verify, do_reset, record_uid, conc):
        total = len(devs)
        ok = 0
        fail = 0
        done = 0

        self.log("========================================")
        self.log(f"[开始] 选中设备数={total}  并行数={conc}")
        self.log(f"[固件] {fw}")
        if is_hex_file(fw):
            self.log("[说明] HEX 自带地址，界面地址框将被忽略。")
        else:
            self.log(f"[地址] {addr}")
        self.log(f"[UID->SN] {'开启' if record_uid else '关闭'}  (UID_BASE=0x{UID_BASE_ADDR:08X})")
        self.log("========================================")

        # 线程池并行
        futures = []
        with ThreadPoolExecutor(max_workers=conc) as ex:
            for d in devs:
                if self.stop_flag.is_set():
                    break
                fut = ex.submit(
                    flash_one_device,
                    d, fw, addr, verify, do_reset, record_uid,
                    self.uid_table, self.uid_lock, self.stop_flag, self.log
                )
                futures.append(fut)

            # as_completed：按完成顺序汇总
            for fut in as_completed(futures):
                if self.stop_flag.is_set():
                    # 尝试取消未开始的任务（已在跑的取消不了）
                    for x in futures:
                        x.cancel()
                try:
                    res = fut.result()
                except Exception as e:
                    self.log(f"[任务异常] {e}")
                    continue

                sn = res.get("sn")
                com = res.get("com")
                done += 1

                self.log(f"\n[{done}/{total}] SN={sn} COM={com}")
                self.log((res.get("out_flash") or "").rstrip())

                if res.get("flash_ok"):
                    ok += 1
                    self.log(f"[结果] OK   (OK={ok} / FAIL={fail})")
                else:
                    fail += 1
                    self.log(f"[结果] FAIL rc={res.get('flash_rc')} (OK={ok} / FAIL={fail})")

                if record_uid:
                    uid = res.get("uid") or ""
                    if uid:
                        if res.get("uid_overwrite"):
                            self.log(f"[UID] {uid}  (重复UID：已覆盖为最新 SN={sn})")
                        else:
                            self.log(f"[UID] {uid}  (已写入表)")
                    else:
                        self.log("[UID] 读取失败（请看下面输出）")
                        self.log((res.get("out_uid") or "").rstrip())
                        self.log(f"[UID] read_rc={res.get('uid_rc')}")

        self.log("\n========================================")
        if self.stop_flag.is_set():
            self.log(f"[结束] 已停止。完成 {done}/{total}  OK={ok} FAIL={fail}")
        else:
            self.log(f"[完成] OK={ok} FAIL={fail}")
        self.log(f"[输出] UID/SN 表：{self.table_path}")
        self.log("========================================")

        self.after(0, self._flash_done_ui)

    def _flash_done_ui(self):
        self.flash_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)

if __name__ == "__main__":
    app = App()
    app.mainloop()
