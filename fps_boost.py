import os
import sys
import time
import psutil
import tkinter as tk
from tkinter import ttk, messagebox

# do NOT change any of these, it will brick your system.
BLOCKLIST = {
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
    "lsass.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "explorer.exe", "sihost.exe",
    "conhost.exe", "fontdrvhost.exe", "taskhostw.exe", "runtimebroker.exe",

    "msmpeng.exe", "securityhealthservice.exe", "securityhealthsystray.exe",

    "nvcontainer.exe", "nvidia share.exe", "nvidia web helper.exe",
    "amdrssrcn.exe", "radeonsoftware.exe",
    "audiodg.exe",

    "easyanticheat.exe", "easyanticheat_launcher.exe",
    "beservice.exe", "bedaisy.exe", "battleye.exe",
    "vgc.exe", "vgtray.exe",

    "cmd.exe", "powershell.exe", "wt.exe", "python.exe", "pythonw.exe",
}
PROTECT_SYSTEM_OWNED = True


def normalize(name: str) -> str:
    return (name or "").strip().lower()


def fmt_bytes(n: int) -> str:
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.1f}{unit}"
        n /= 1024.0
    return f"{n:.1f}PB"


def is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def get_owner(proc: psutil.Process) -> str:
    try:
        return proc.username() or ""
    except Exception:
        return ""


def safe_to_stop(proc: psutil.Process):
    """
    Return (ok: bool, reason: str)
    """
    try:
        name = normalize(proc.name())
        if not name:
            return False, "Unknown name"

        if proc.pid in (0, 4):
            return False, "Kernel/System process"

        if name in BLOCKLIST:
            return False, "Protected (critical/common)"

        if PROTECT_SYSTEM_OWNED:
            owner = (get_owner(proc) or "").lower()
            if owner.endswith("\\system") or owner == "system" or owner.endswith("\\localsystem"):
                return False, "Owned by SYSTEM"

        try:
            if proc.pid > 0 and proc.ppid() == 0:
                return True, "OK (service-like parent)"
        except Exception:
            pass

        return True, "OK"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False, "No access"
    except Exception as e:
        return False, f"Error: {e}"


def take_snapshot():
    """
    Sample CPU% by priming then sleeping briefly.
    Returns list of dict rows.
    """
    for p in psutil.process_iter(["pid", "name"]):
        try:
            p.cpu_percent(None)
        except Exception:
            pass

    time.sleep(0.7)

    rows = []
    for p in psutil.process_iter(["pid", "name", "memory_info"]):
        try:
            pid = p.pid
            name = p.name() or ""
            cpu = p.cpu_percent(None)
            mem = p.info["memory_info"].rss if p.info.get("memory_info") else 0
            owner = get_owner(p)
            ok, reason = safe_to_stop(p)

            rows.append({
                "pid": pid,
                "name": name,
                "cpu": float(cpu),
                "mem": int(mem),
                "owner": owner,
                "ok": bool(ok),
                "reason": reason,
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    rows.sort(key=lambda r: (r["cpu"], r["mem"]), reverse=True)
    return rows


class FPSHelperUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FPS Helper — Safe Process Stopper")
        self.geometry("1100x650")
        self.minsize(950, 550)

        self.rows = []          
        self.vars = {}          

        self._build_ui()

        if os.name != "nt":
            messagebox.showerror("Unsupported OS", "This app is intended for Windows.")
            self.after(100, self.destroy)
            return

        if not is_admin():
            self.status_var.set("Not running as admin — some processes may be inaccessible.")
        else:
            self.status_var.set("Running as admin.")

        self.refresh()

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Processes", font=("Segoe UI", 14, "bold")).pack(side="left")

        self.search_var = tk.StringVar()
        search = ttk.Entry(top, textvariable=self.search_var, width=35)
        search.pack(side="left", padx=(15, 8))
        search.insert(0, "filter (name/owner/pid)")
        search.bind("<FocusIn>", self._clear_search_hint)
        search.bind("<KeyRelease>", lambda e: self._render_table())

        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="left", padx=6)
        ttk.Button(top, text="Stop Selected", command=self.stop_selected).pack(side="left", padx=6)

        ttk.Separator(self).pack(fill="x")

        mid = ttk.Frame(self, padding=(10, 10))
        mid.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(mid, highlightthickness=0)
        self.scroll = ttk.Scrollbar(mid, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scroll.set)

        self.inner = ttk.Frame(self.canvas)
        self.inner_id = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scroll.pack(side="right", fill="y")

        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        self.header = ttk.Frame(self.inner)
        self.header.pack(fill="x", pady=(0, 6))

        cols = [
            ("Select", 70),
            ("PID", 70),
            ("CPU %", 80),
            ("RAM", 95),
            ("Name", 280),
            ("Owner", 220),
            ("Status", 240),
        ]
        self.col_widths = [w for _, w in cols]

        for i, (label, width) in enumerate(cols):
            l = ttk.Label(self.header, text=label, anchor="w", font=("Segoe UI", 10, "bold"))
            l.grid(row=0, column=i, sticky="w")
            self.header.grid_columnconfigure(i, minsize=width)

        ttk.Separator(self.inner).pack(fill="x", pady=(0, 6))

        self.rows_frame = ttk.Frame(self.inner)
        self.rows_frame.pack(fill="both", expand=True)

        bottom = ttk.Frame(self, padding=10)
        bottom.pack(fill="x")
        self.status_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="left")

        self.count_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=self.count_var).pack(side="right")

    def _clear_search_hint(self, event):
        if self.search_var.get().strip().lower() == "filter (name/owner/pid)":
            self.search_var.set("")

    def _on_inner_configure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        self.canvas.itemconfig(self.inner_id, width=event.width)

    def refresh(self):
        self.status_var.set("Refreshing…")
        self.update_idletasks()

        self.rows = take_snapshot()

        new_vars = {}
        for r in self.rows:
            pid = r["pid"]
            if pid in self.vars:
                new_vars[pid] = self.vars[pid]
            else:
                new_vars[pid] = tk.BooleanVar(value=False)
        self.vars = new_vars

        self._render_table()
        self.status_var.set(self.status_var.get().replace("Refreshing…", "Ready."))

    def _render_table(self):
        for child in self.rows_frame.winfo_children():
            child.destroy()

        q = self.search_var.get().strip().lower()
        if q == "filter (name/owner/pid)":
            q = ""

        filtered = []
        for r in self.rows:
            hay = f"{r['pid']} {r['name']} {r['owner']}".lower()
            if not q or q in hay:
                filtered.append(r)

        for i, r in enumerate(filtered):
            pid = r["pid"]
            ok = r["ok"]
            reason = r["reason"]

            row = ttk.Frame(self.rows_frame)
            row.pack(fill="x", pady=1)

            cb = ttk.Checkbutton(
                row,
                variable=self.vars[pid],
                state=("normal" if ok else "disabled")
            )
            cb.grid(row=0, column=0, sticky="w")
            row.grid_columnconfigure(0, minsize=self.col_widths[0])

            ttk.Label(row, text=str(pid), anchor="w").grid(row=0, column=1, sticky="w")
            row.grid_columnconfigure(1, minsize=self.col_widths[1])

            ttk.Label(row, text=f"{r['cpu']:.1f}", anchor="w").grid(row=0, column=2, sticky="w")
            row.grid_columnconfigure(2, minsize=self.col_widths[2])

            ttk.Label(row, text=fmt_bytes(r["mem"]), anchor="w").grid(row=0, column=3, sticky="w")
            row.grid_columnconfigure(3, minsize=self.col_widths[3])

            ttk.Label(row, text=r["name"], anchor="w").grid(row=0, column=4, sticky="w")
            row.grid_columnconfigure(4, minsize=self.col_widths[4])

            ttk.Label(row, text=r["owner"][:40], anchor="w").grid(row=0, column=5, sticky="w")
            row.grid_columnconfigure(5, minsize=self.col_widths[5])

            status_text = reason if ok else f"PROTECTED — {reason}"
            ttk.Label(row, text=status_text, anchor="w").grid(row=0, column=6, sticky="w")
            row.grid_columnconfigure(6, minsize=self.col_widths[6])

        self.count_var.set(f"Showing {len(filtered)} / {len(self.rows)} processes")

    def stop_selected(self):
        selected_pids = []
        selected_names = []
        for r in self.rows:
            pid = r["pid"]
            if self.vars.get(pid) and self.vars[pid].get():
                try:
                    p = psutil.Process(pid)
                    ok, reason = safe_to_stop(p)
                    if ok:
                        selected_pids.append(pid)
                        selected_names.append(p.name())
                    else:
                        self.vars[pid].set(False)
                except Exception:
                    self.vars[pid].set(False)

        if not selected_pids:
            messagebox.showinfo("Nothing selected", "No safe, selected processes to stop.")
            return

        preview = "\n".join([f"PID {pid} — {name}" for pid, name in zip(selected_pids, selected_names)])
        if len(preview) > 1200:
            preview = preview[:1200] + "\n…"

        if not messagebox.askyesno(
            "Confirm stop",
            "You’re about to terminate these processes:\n\n"
            f"{preview}\n\n"
            "Continue?"
        ):
            return

        killed = 0
        denied = 0
        errors = 0

        for pid in selected_pids:
            try:
                p = psutil.Process(pid)
                p.terminate()
            except psutil.AccessDenied:
                denied += 1
            except psutil.NoSuchProcess:
                pass
            except Exception:
                errors += 1

        time.sleep(1.0)
        for pid in selected_pids:
            try:
                p = psutil.Process(pid)
                if p.is_running():
                    p.kill()
                killed += 1
            except psutil.AccessDenied:
                denied += 1
            except psutil.NoSuchProcess:
                pass
            except Exception:
                errors += 1

        messagebox.showinfo(
            "Done",
            f"Stopped: {killed}\nAccess denied: {denied}\nErrors: {errors}\n\nTip: click Refresh to see updated usage."
        )
        self.refresh()


def main():
    if os.name != "nt":
        print("This app is intended for Windows.")
        sys.exit(1)
    app = FPSHelperUI()
    app.mainloop()


if __name__ == "__main__":
    main()
