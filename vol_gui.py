#!/usr/bin/env python3
"""Graphical front-end for Volatility 3.

Pick a memory image, let the tool work out which operating system it came
from, then click the plugins to run.  Every run is written to its own file in
the output folder, and anything Volatility complains about is shown in the log.

The GUI never talks to the framework directly while analysing: each run is a
separate ``vol.py`` process, so a plugin that hangs or crashes cannot take the
window down with it and can always be stopped.
"""

import collections
import contextlib
import csv
import dataclasses
import datetime
import io
import json
import os
import queue
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from tkinter import font as tkfont
from typing import Any, Deque, Dict, List, Optional, Tuple

BASE_DIR = Path(__file__).resolve().parent
VOL_PY = BASE_DIR / "vol.py"
DEFAULT_OUTPUT_ROOT = BASE_DIR / "output"
SETTINGS_FILE = Path.home() / ".vol_gui.json"

OS_LABELS = {"windows": "Windows", "linux": "Linux", "mac": "Mac"}

THEMES = {
    "dark": {
        "bg": "#0d1117",
        "panel": "#161b22",
        "raised": "#21262d",
        "input": "#0d1117",
        "border": "#30363d",
        "text": "#e6edf3",
        "muted": "#8b949e",
        "accent": "#2f81f7",
        "accent_hover": "#539bf5",
        "accent_text": "#ffffff",
        "danger": "#da3633",
        "danger_hover": "#f85149",
        "select": "#1f3a5f",
        "stripe": "#1a2029",
        "info": "#6cb6ff",
        "ok": "#3fb950",
        "warn": "#d29922",
        "error": "#f85149",
    },
    "light": {
        "bg": "#eef1f5",
        "panel": "#ffffff",
        "raised": "#f3f4f6",
        "input": "#ffffff",
        "border": "#d0d7de",
        "text": "#1f2328",
        "muted": "#656d76",
        "accent": "#0969da",
        "accent_hover": "#0860c4",
        "accent_text": "#ffffff",
        "danger": "#cf222e",
        "danger_hover": "#a40e26",
        "select": "#cfe3ff",
        "stripe": "#f6f8fa",
        "info": "#0969da",
        "ok": "#1a7f37",
        "warn": "#9a6700",
        "error": "#cf222e",
    },
}

# OS badge in the header: background, text colour
OS_BADGES = {
    "windows": ("#2f81f7", "#ffffff"),
    "linux": ("#e3a008", "#1f2328"),
    "mac": ("#8957e5", "#ffffff"),
}

# Label shown in the GUI -> (volatility renderer, output file extension).
# Volatility's own text tables pad every column to its widest value, which is
# unreadable for anything with a long field, so the table formats are rendered
# as CSV and laid out by this program instead.
RENDERERS = {
    "Tabel rapi (.txt)": ("csv", ".txt"),
    "CSV (.csv)": ("csv", ".csv"),
    "JSON (.json)": ("json", ".json"),
    "JSON Lines (.jsonl)": ("jsonl", ".jsonl"),
}

# Plugins can produce hundreds of thousands of rows; the file always gets all
# of them, the window only the first ones so it stays responsive.
MAX_VIEW_LINES = 3000
MAX_TABLE_ROWS = 20000
TABLE_ROWS_PER_TICK = 400
PROGRESS_INTERVAL = 0.1

# Layout of the text tables written to the output files
MAX_COLUMN_WIDTH = 80
VERTICAL_MAX_ROWS = 5
VERTICAL_MIN_WIDTH = 160

# Layout of the result table in the window
MAX_CELL_VIEW = 300
MAX_COLUMN_PIXELS = 520

csv.field_size_limit(2**31 - 1)

Row = Tuple[int, List[str]]  # tree depth, cells

# File signatures that identify the operating system without running a plugin
OS_SIGNATURES = {
    b"PAGEDU64": ("windows", "Windows crash dump 64-bit"),
    b"PAGEDUMP": ("windows", "Windows crash dump 32-bit"),
}

PROGRESS_RE = re.compile(r"^Progress:\s*([0-9.]+)\s*(.*)$")
INTEGER_RE = re.compile(r"^-?\d+$")
WINDOWS_PATH_RE = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def normalize_path(text: str) -> str:
    """Cleans up a path typed or pasted by the user.

    Under WSL a pasted ``C:\\dumps\\mem.raw`` is turned into ``/mnt/c/dumps/mem.raw``.
    """
    text = text.strip().strip('"').strip("'")
    if not text:
        return text
    match = WINDOWS_PATH_RE.match(text)
    if match and os.name != "nt":
        drive, rest = match.groups()
        return f"/mnt/{drive.lower()}/" + rest.replace("\\", "/")
    return os.path.expanduser(text)


def open_folder(path: Path) -> None:
    """Opens a folder in the platform's file manager."""
    if os.name == "nt":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif shutil.which("wslpath") and shutil.which("explorer.exe"):
        win_path = subprocess.run(
            ["wslpath", "-w", str(path)], capture_output=True, text=True
        ).stdout.strip()
        subprocess.Popen(["explorer.exe", win_path])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def load_plugin_catalog() -> Tuple[Dict[str, Dict[str, Any]], List[str]]:
    """Asks the framework for every plugin and the options each one accepts.

    Only the requirements that ``vol.py`` exposes as command line arguments are
    kept (see CommandLine.populate_requirements_argparse).

    Returns:
        The catalog keyed by plugin name, and the modules that failed to import
    """
    sys.path.insert(0, str(BASE_DIR))
    import volatility3.plugins
    from volatility3 import framework
    from volatility3.framework import interfaces
    from volatility3.framework.configuration import requirements

    failures = framework.import_files(volatility3.plugins, True)
    catalog: Dict[str, Dict[str, Any]] = {}
    for name, plugin in sorted(framework.list_plugins().items()):
        options = []
        for req in plugin.get_requirements():
            option: Dict[str, Any] = {
                "name": req.name,
                "description": req.description or "",
                "optional": req.optional,
                "default": req.default,
                "choices": None,
            }
            if isinstance(req, requirements.BooleanRequirement):
                option["kind"] = "bool"
            elif isinstance(req, interfaces.configuration.SimpleTypeRequirement):
                option["kind"] = "value"
            elif isinstance(req, requirements.ListRequirement):
                option["kind"] = "list"
            elif isinstance(req, requirements.ChoiceRequirement):
                option["kind"] = "choice"
                option["choices"] = list(req.choices)
            else:
                continue
            options.append(option)
        doc = (plugin.__doc__ or "").strip()
        catalog[name] = {
            "doc": " ".join(doc.split()) if doc else "(tidak ada deskripsi)",
            "options": options,
        }
    return catalog, [str(failure) for failure in failures]


def sniff_os(path: str) -> Optional[Tuple[str, str]]:
    """Recognises the operating system from the file header, when it says so."""
    try:
        with open(path, "rb") as image:
            header = image.read(8)
    except OSError:
        return None
    return OS_SIGNATURES.get(header)


def clean_cell(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n").expandtabs(4).strip("\n")


def format_record(columns: List[str], cells: List[str]) -> str:
    """Lays one row out vertically, one ``column : value`` line per field."""
    label_width = max((len(column) for column in columns), default=0)
    lines = []
    for column, cell in zip(columns, cells):
        first, *rest = clean_cell(cell).split("\n")
        lines.append(f"{column.ljust(label_width)} : {first}")
        lines += [" " * (label_width + 3) + line for line in rest]
    return "\n".join(lines) + "\n"


def format_table(columns: List[str], rows: List[Row]) -> str:
    """Lays a plugin result out as an aligned text table.

    Columns are only as wide as their content, long values wrap inside their
    column instead of stretching it, and the last column is never padded.  A
    result with multi-line values, or with a few very wide rows, is written as
    vertical records instead.
    """
    if not rows:
        return "(tidak ada hasil)\n"
    count = len(columns)
    table = []
    for depth, cells in rows:
        cells = [clean_cell(cell) for cell in cells[:count]]
        cells += [""] * (count - len(cells))
        if cells:
            cells[0] = "  " * depth + cells[0]
        table.append(cells)

    natural = [
        max(len(columns[i]), max(len(line) for cells in table for line in cells[i].split("\n")))
        for i in range(count)
    ]
    # Multi-line values (hexdumps, disassembly) cannot sit side by side in a table
    multiline = any("\n" in cell for cells in table for cell in cells)
    few_wide = len(table) <= VERTICAL_MAX_ROWS and sum(natural) + 2 * count > VERTICAL_MIN_WIDTH
    if multiline or few_wide:
        records = [format_record(columns, cells) for cells in table]
        if len(records) == 1:
            return records[0]
        return "\n".join(f"--- Baris {n} ---\n{record}" for n, record in enumerate(records, 1))

    widths = [min(width, MAX_COLUMN_WIDTH) for width in natural]
    numeric = [all(INTEGER_RE.match(cells[i]) for cells in table) for i in range(count)]

    def render(parts: List[str]) -> str:
        padded = [
            part.rjust(widths[i]) if numeric[i] else part.ljust(widths[i])
            for i, part in enumerate(parts)
        ]
        return "  ".join(padded).rstrip()

    out = [render(columns), render(["-" * width for width in widths])]
    for cells in table:
        wrapped = []
        for i, cell in enumerate(cells):
            lines: List[str] = []
            for line in cell.split("\n"):
                if i < count - 1 and len(line) > widths[i]:
                    lines += [line[k : k + widths[i]] for k in range(0, len(line), widths[i])]
                else:
                    lines.append(line)
            wrapped.append(lines)
        for k in range(max(len(lines) for lines in wrapped)):
            out.append(render([lines[k] if k < len(lines) else "" for lines in wrapped]))
    return "\n".join(out) + "\n"


def sort_key(text: str) -> Tuple[int, Any]:
    try:
        return (0, int(text.strip(), 0))
    except ValueError:
        return (1, text.strip().lower())


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.2f} {unit}"
        value /= 1024
    return f"{value:.2f} TB"


def plugin_os(name: str) -> str:
    prefix = name.split(".", 1)[0]
    return prefix if prefix in OS_LABELS else "general"


def explain_failure(text: str, os_name: Optional[str]) -> Optional[str]:
    """Turns the common Volatility failures into a plain hint for the user."""
    symbols_failed = "symbol table requirement was not fulfilled" in text
    # Without a matching ISF Volatility cannot build the Linux/Mac kernel layer
    # either, so there a missing symbol table is the likelier cause of both.
    if symbols_failed and os_name in ("linux", "mac"):
        return (
            "Kemungkinan besar symbol table (ISF) untuk kernel ini belum ada. Buat file "
            "ISF yang cocok dengan banner kernel (dwarf2json), lalu taruh di "
            f"{BASE_DIR / 'volatility3' / 'symbols' / os_name}. Jika ISF sudah ada, "
            "berarti memory dump rusak atau formatnya tidak didukung."
        )
    if "translation layer requirement was not fulfilled" in text:
        return (
            "Memory dump tidak bisa dibaca: file bukan memory image yang valid, "
            "rusak/terpotong, atau bukan dari OS yang dipilih."
        )
    if symbols_failed:
        return (
            "Symbol table Windows tidak ditemukan. Volatility perlu mengunduh PDB "
            "dari Microsoft - periksa koneksi internet lalu coba lagi."
        )
    return None


@dataclasses.dataclass(eq=False)
class Job:
    """One vol.py invocation."""

    kind: str  # "plugin", "detect_windows" or "detect_banners"
    plugin: str
    dump: str
    renderer: str
    extra_args: List[str] = dataclasses.field(default_factory=list)
    outfile: Optional[Path] = None
    dump_dir: Optional[Path] = None
    # Non-result text Volatility printed on stdout (its error explanations)
    captured: List[str] = dataclasses.field(default_factory=list)
    errors: List[str] = dataclasses.field(default_factory=list)
    # The parsed result of a "csv" run; columns stays None until the header arrives
    columns: Optional[List[str]] = None
    rows: List[Row] = dataclasses.field(default_factory=list)
    cancelled: bool = False

    @property
    def tabular(self) -> bool:
        return self.renderer == "csv"

    def command(self) -> List[str]:
        cmd = [sys.executable, "-u", str(VOL_PY), "-f", self.dump, "-r", self.renderer]
        if self.dump_dir:
            cmd += ["-o", str(self.dump_dir)]
        return cmd + [self.plugin] + self.extra_args


class VolatilityGUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Volatility 3 GUI")
        width = min(1500, int(self.winfo_screenwidth() * 0.92))
        height = min(960, int(self.winfo_screenheight() * 0.88))
        self.geometry(f"{width}x{height}")
        self.minsize(1100, 700)

        self.catalog: Dict[str, Dict[str, Any]] = {}
        self.option_vars: Dict[str, Dict[str, tk.Variable]] = {}
        self.extra_vars: Dict[str, tk.StringVar] = {}
        self.events: "queue.Queue[Tuple[Any, ...]]" = queue.Queue()
        self.jobs: Deque[Job] = collections.deque()
        self.current: Optional[Job] = None
        self.proc: Optional[subprocess.Popen] = None
        self.batch_total = 0
        self.detected_os: Optional[str] = None
        self.detect_error = ""
        self._outdir_auto = True
        self.table_job: Optional[Job] = None
        self.table_shown = 0
        self.table_chars: List[int] = []
        self.table_sort: Tuple[int, bool] = (-1, False)
        self.badge_state = "idle"  # "idle", "detecting" or "failed" while no OS is chosen
        self.theme = self._load_settings().get("theme", "dark")
        if self.theme not in THEMES:
            self.theme = "dark"

        self.dump_var = tk.StringVar()
        self.outdir_var = tk.StringVar()
        self.os_var = tk.StringVar()
        self.format_var = tk.StringVar(value=next(iter(RENDERERS)))
        self.filter_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Memuat daftar plugin...")
        self.detect_var = tk.StringVar(value="Belum ada memory dump yang dipilih.")
        self.result_var = tk.StringVar(value="Belum ada hasil. Jalankan plugin untuk melihatnya di sini.")
        self.file_info_var = tk.StringVar(value="")
        self.details_title = tk.StringVar(value="OPSI PLUGIN")
        self.percent_var = tk.StringVar(value="")

        self._build_style()
        self._build_widgets()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        threading.Thread(target=self._load_catalog_thread, daemon=True).start()
        self.after(60, self._poll_events)

    # ------------------------------------------------------------------ UI

    def _build_style(self) -> None:
        self.style = ttk.Style(self)
        if "clam" in self.style.theme_names():
            self.style.theme_use("clam")

        families = set(tkfont.families(self))
        ui = next(
            (f for f in ("Segoe UI", "Inter", "Ubuntu", "Noto Sans", "DejaVu Sans") if f in families),
            tkfont.nametofont("TkDefaultFont").actual("family"),
        )
        mono = next(
            (
                f
                for f in ("Cascadia Mono", "Consolas", "JetBrains Mono", "DejaVu Sans Mono", "Ubuntu Mono")
                if f in families
            ),
            tkfont.nametofont("TkFixedFont").actual("family"),
        )
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            tkfont.nametofont(name).configure(family=ui, size=10)
        self.font_bold = tkfont.Font(family=ui, size=10, weight="bold")
        self.font_section = tkfont.Font(family=ui, size=9, weight="bold")
        self.font_title = tkfont.Font(family=ui, size=15, weight="bold")
        self.font_logo = tkfont.Font(family=ui, size=20, weight="bold")
        self.mono = tkfont.Font(family=mono, size=10)
        self.table_font = tkfont.nametofont("TkDefaultFont")

    def _apply_theme(self) -> None:
        """(Re)colours every widget from the current palette."""
        p = THEMES[self.theme]
        style = self.style
        self.configure(background=p["bg"])

        style.configure(
            ".",
            background=p["panel"],
            foreground=p["text"],
            fieldbackground=p["input"],
            bordercolor=p["border"],
            lightcolor=p["panel"],
            darkcolor=p["panel"],
            troughcolor=p["panel"],
            focuscolor=p["accent"],
            selectbackground=p["select"],
            selectforeground=p["text"],
            insertcolor=p["text"],
            arrowcolor=p["muted"],
        )
        style.configure("TFrame", background=p["panel"])
        style.configure("Bg.TFrame", background=p["bg"])
        style.configure("Header.TFrame", background=p["panel"])
        style.configure("Line.TFrame", background=p["border"])
        style.configure(
            "Card.TFrame",
            background=p["panel"],
            bordercolor=p["border"],
            lightcolor=p["border"],
            darkcolor=p["border"],
            relief="solid",
            borderwidth=1,
        )
        style.configure("TLabel", background=p["panel"], foreground=p["text"])
        style.configure("Hint.TLabel", foreground=p["muted"])
        style.configure("Section.TLabel", foreground=p["muted"], font=self.font_section)
        style.configure("AppTitle.TLabel", font=self.font_title)
        style.configure("AppSub.TLabel", foreground=p["muted"])
        style.configure("Logo.TLabel", foreground=p["accent"], font=self.font_logo)

        flat = {"lightcolor": p["raised"], "darkcolor": p["raised"]}
        style.configure(
            "TButton",
            background=p["raised"],
            foreground=p["text"],
            bordercolor=p["border"],
            padding=(14, 6),
            focusthickness=0,
            **flat,
        )
        style.map(
            "TButton",
            background=[("disabled", p["panel"]), ("pressed", p["border"]), ("active", p["border"])],
            foreground=[("disabled", p["muted"])],
            lightcolor=[("active", p["border"])],
            darkcolor=[("active", p["border"])],
        )
        for name, base, hover in (
            ("Accent.TButton", p["accent"], p["accent_hover"]),
            ("Danger.TButton", p["danger"], p["danger_hover"]),
        ):
            style.configure(
                name,
                background=base,
                foreground=p["accent_text"],
                bordercolor=base,
                lightcolor=base,
                darkcolor=base,
                font=self.font_bold,
                padding=(16, 7),
            )
            style.map(
                name,
                background=[("disabled", p["raised"]), ("pressed", hover), ("active", hover)],
                foreground=[("disabled", p["muted"])],
                bordercolor=[("disabled", p["border"]), ("active", hover)],
                lightcolor=[("disabled", p["raised"]), ("active", hover)],
                darkcolor=[("disabled", p["raised"]), ("active", hover)],
            )

        field = {
            "fieldbackground": p["input"],
            "foreground": p["text"],
            "bordercolor": p["border"],
            "lightcolor": p["input"],
            "darkcolor": p["input"],
            "insertcolor": p["text"],
        }
        style.configure("TEntry", padding=(8, 5), **field)
        style.map("TEntry", bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["accent"])])
        style.configure("TCombobox", padding=(8, 4), background=p["raised"], arrowcolor=p["muted"], **field)
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", p["input"])],
            foreground=[("readonly", p["text"])],
            selectbackground=[("readonly", p["input"])],
            selectforeground=[("readonly", p["text"])],
            bordercolor=[("focus", p["accent"])],
            background=[("active", p["border"])],
        )
        self.option_add("*TCombobox*Listbox.background", p["input"])
        self.option_add("*TCombobox*Listbox.foreground", p["text"])
        self.option_add("*TCombobox*Listbox.selectBackground", p["accent"])
        self.option_add("*TCombobox*Listbox.selectForeground", p["accent_text"])

        style.configure(
            "TCheckbutton",
            background=p["panel"],
            foreground=p["text"],
            indicatorbackground=p["input"],
            indicatorforeground=p["accent_text"],
            upperbordercolor=p["border"],
            lowerbordercolor=p["border"],
            indicatormargin=(0, 0, 8, 0),
        )
        style.map(
            "TCheckbutton",
            background=[("active", p["panel"])],
            indicatorbackground=[("selected", p["accent"])],
        )

        style.configure(
            "Treeview",
            background=p["panel"],
            fieldbackground=p["panel"],
            foreground=p["text"],
            bordercolor=p["border"],
            lightcolor=p["panel"],
            darkcolor=p["panel"],
            rowheight=26,
        )
        style.map("Treeview", background=[("selected", p["select"])], foreground=[("selected", p["text"])])
        style.configure(
            "Treeview.Heading",
            background=p["raised"],
            foreground=p["muted"],
            bordercolor=p["border"],
            lightcolor=p["raised"],
            darkcolor=p["raised"],
            relief="flat",
            padding=(8, 5),
            font=self.font_section,
        )
        style.map("Treeview.Heading", background=[("active", p["border"])])

        style.configure("TNotebook", background=p["panel"], bordercolor=p["border"], tabmargins=(0, 0, 0, 0))
        style.configure(
            "TNotebook.Tab",
            background=p["panel"],
            foreground=p["muted"],
            bordercolor=p["border"],
            lightcolor=p["panel"],
            darkcolor=p["panel"],
            padding=(18, 7),
            font=self.font_bold,
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", p["raised"])],
            foreground=[("selected", p["text"])],
            lightcolor=[("selected", p["accent"])],
        )

        style.configure(
            "TScrollbar",
            background=p["raised"],
            troughcolor=p["panel"],
            bordercolor=p["panel"],
            lightcolor=p["raised"],
            darkcolor=p["raised"],
            arrowcolor=p["muted"],
            gripcount=0,
        )
        style.map("TScrollbar", background=[("active", p["border"])])
        style.configure(
            "Accent.Horizontal.TProgressbar",
            background=p["accent"],
            troughcolor=p["raised"],
            bordercolor=p["raised"],
            lightcolor=p["accent"],
            darkcolor=p["accent"],
            thickness=10,
        )
        style.configure("TPanedwindow", background=p["bg"])
        style.configure(
            "Sash", sashthickness=12, gripcount=0, background=p["bg"], lightcolor=p["bg"], bordercolor=p["bg"]
        )

        for text in (self.log, self.detail):
            text.configure(
                background=p["input"],
                foreground=p["text"],
                insertbackground=p["text"],
                selectbackground=p["select"],
                selectforeground=p["text"],
                highlightbackground=p["border"],
                highlightcolor=p["border"],
            )
        for tag in ("info", "ok", "error"):
            self.log.tag_configure(tag, foreground=p[tag])
        self.log.tag_configure("stderr", foreground=p["warn"])
        self.options_canvas.configure(background=p["panel"])
        self.tree.tag_configure("group", foreground=p["accent"], font=self.font_bold)
        self.table.tag_configure("odd", background=p["stripe"])
        self.theme_button.configure(text="☀  Mode terang" if self.theme == "dark" else "☾  Mode gelap")
        self._update_badge()

    def toggle_theme(self) -> None:
        self.theme = "light" if self.theme == "dark" else "dark"
        self._apply_theme()
        self._save_settings({"theme": self.theme})

    @staticmethod
    def _load_settings() -> Dict[str, Any]:
        try:
            return json.loads(SETTINGS_FILE.read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    @staticmethod
    def _save_settings(settings: Dict[str, Any]) -> None:
        with contextlib.suppress(OSError):
            SETTINGS_FILE.write_text(json.dumps(settings), "utf-8")

    def _update_badge(self) -> None:
        """Shows the operating system the plugin list is for in the header."""
        p = THEMES[self.theme]
        os_name = self.selected_os()
        if os_name:
            background, foreground = OS_BADGES[os_name]
            text = OS_LABELS[os_name].upper()
        elif self.badge_state == "detecting":
            background, foreground, text = p["warn"], "#1f2328", "MENDETEKSI..."
        elif self.badge_state == "failed":
            background, foreground, text = p["danger"], "#ffffff", "TIDAK TERBACA"
        else:
            background, foreground, text = p["raised"], p["muted"], "BELUM ADA DUMP"
        self.badge.configure(text=f"  {text}  ", background=background, foreground=foreground)

    def _card(self, parent: tk.Widget, title: Any) -> Tuple[ttk.Frame, ttk.Frame]:
        """A bordered panel with a small heading; returns the panel and its body."""
        card = ttk.Frame(parent, style="Card.TFrame", padding=(14, 10, 14, 12))
        if isinstance(title, tk.StringVar):
            ttk.Label(card, textvariable=title, style="Section.TLabel").pack(anchor="w")
        else:
            ttk.Label(card, text=title, style="Section.TLabel").pack(anchor="w")
        body = ttk.Frame(card)
        body.pack(fill="both", expand=True, pady=(8, 0))
        return card, body

    def _build_widgets(self) -> None:
        # Header
        header = ttk.Frame(self, style="Header.TFrame", padding=(18, 10))
        header.pack(fill="x")
        ttk.Label(header, text="◆", style="Logo.TLabel").pack(side="left")
        titles = ttk.Frame(header, style="Header.TFrame")
        titles.pack(side="left", padx=(10, 0))
        ttk.Label(titles, text="Volatility 3", style="AppTitle.TLabel").pack(anchor="w")
        ttk.Label(
            titles, text="Memory forensics tanpa command line", style="AppSub.TLabel"
        ).pack(anchor="w")
        self.theme_button = ttk.Button(header, command=self.toggle_theme)
        self.theme_button.pack(side="right")
        self.badge = tk.Label(header, font=self.font_section, padx=10, pady=5, borderwidth=0)
        self.badge.pack(side="right", padx=(0, 14))
        ttk.Label(header, text="Sistem operasi", style="Hint.TLabel").pack(side="right", padx=(0, 8))
        ttk.Frame(self, style="Line.TFrame", height=1).pack(fill="x")

        # Status bar, packed before the body so it survives a small window
        status = ttk.Frame(self, style="Header.TFrame", padding=(14, 10))
        status.pack(side="bottom", fill="x")
        ttk.Frame(self, style="Line.TFrame", height=1).pack(side="bottom", fill="x")
        self.run_button = ttk.Button(
            status, text="▶  Jalankan plugin", style="Accent.TButton", command=self.run_selected
        )
        self.run_button.pack(side="left")
        self.stop_button = ttk.Button(
            status, text="■  Stop", style="Danger.TButton", command=self.stop, state="disabled"
        )
        self.stop_button.pack(side="left", padx=8)
        ttk.Button(status, text="Bersihkan log", command=self.clear_log).pack(side="left")
        ttk.Label(status, textvariable=self.percent_var, style="Hint.TLabel", width=5, anchor="e").pack(
            side="right"
        )
        self.progress = ttk.Progressbar(
            status, length=220, maximum=100, style="Accent.Horizontal.TProgressbar"
        )
        self.progress.pack(side="right", padx=(0, 6))
        ttk.Label(status, textvariable=self.status_var, style="Hint.TLabel", anchor="e").pack(
            side="right", fill="x", expand=True, padx=12
        )

        body = ttk.Frame(self, style="Bg.TFrame", padding=(14, 12, 14, 12))
        body.pack(fill="both", expand=True)

        # Evidence
        card, evidence = self._card(body, "BARANG BUKTI")
        card.pack(fill="x")
        evidence.columnconfigure(1, weight=1)
        ttk.Label(evidence, text="Memory dump").grid(row=0, column=0, sticky="w", padx=(0, 12))
        dump_entry = ttk.Entry(evidence, textvariable=self.dump_var)
        dump_entry.grid(row=0, column=1, sticky="ew")
        dump_entry.bind("<Return>", lambda _e: self.detect_os())
        ttk.Button(
            evidence, text="Pilih file...", style="Accent.TButton", command=self.choose_dump
        ).grid(row=0, column=2, sticky="ew", padx=(8, 0))
        ttk.Button(evidence, text="Deteksi ulang", command=self.detect_os).grid(
            row=0, column=3, sticky="ew", padx=(8, 0)
        )

        ttk.Label(evidence, text="Folder output").grid(row=1, column=0, sticky="w", pady=(8, 0))
        outdir_entry = ttk.Entry(evidence, textvariable=self.outdir_var)
        outdir_entry.grid(row=1, column=1, sticky="ew", pady=(8, 0))
        outdir_entry.bind("<Key>", lambda _e: setattr(self, "_outdir_auto", False))
        ttk.Button(evidence, text="Pilih folder...", command=self.choose_outdir).grid(
            row=1, column=2, sticky="ew", padx=(8, 0), pady=(8, 0)
        )
        ttk.Button(evidence, text="Buka folder", command=self.open_outdir).grid(
            row=1, column=3, sticky="ew", padx=(8, 0), pady=(8, 0)
        )

        info = ttk.Frame(evidence)
        info.grid(row=2, column=0, columnspan=4, sticky="ew", pady=(10, 0))
        ttk.Label(info, textvariable=self.file_info_var).pack(side="left")
        ttk.Label(info, textvariable=self.detect_var, style="Hint.TLabel").pack(side="left", padx=(12, 0))
        ttk.Combobox(
            info, textvariable=self.format_var, values=list(RENDERERS), state="readonly", width=18
        ).pack(side="right")
        ttk.Label(info, text="Format output", style="Hint.TLabel").pack(side="right", padx=(16, 8))
        self.os_combo = ttk.Combobox(
            info, textvariable=self.os_var, values=list(OS_LABELS.values()), state="readonly", width=9
        )
        self.os_combo.pack(side="right")
        self.os_combo.bind("<<ComboboxSelected>>", lambda _e: self._refresh_plugins())
        ttk.Label(info, text="Pilih OS manual", style="Hint.TLabel").pack(side="right", padx=(0, 8))

        panes = ttk.PanedWindow(body, orient="horizontal")
        panes.pack(fill="both", expand=True, pady=(12, 0))

        # Left: the plugin list
        card, left = self._card(panes, "PLUGIN")
        panes.add(card, weight=2)
        search = ttk.Frame(left)
        search.pack(fill="x", pady=(0, 8))
        ttk.Label(search, text="Cari", style="Hint.TLabel").pack(side="left", padx=(0, 8))
        ttk.Entry(search, textvariable=self.filter_var).pack(side="left", fill="x", expand=True)
        self.filter_var.trace_add("write", lambda *_a: self._refresh_plugins())

        tree_frame = ttk.Frame(left)
        tree_frame.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(
            tree_frame, columns=("doc",), selectmode="extended", show="tree headings"
        )
        self.tree.heading("#0", text="PLUGIN", anchor="w")
        self.tree.heading("doc", text="DESKRIPSI", anchor="w")
        self.tree.column("#0", width=240, stretch=False)
        self.tree.column("doc", width=320)
        tree_scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._show_plugin_details())
        self.tree.bind("<Double-1>", self._on_double_click)
        self.tree.bind("<Return>", lambda _e: self.run_selected())
        ttk.Label(
            left,
            text="Klik dua kali untuk menjalankan  ·  Ctrl/Shift+klik untuk memilih beberapa",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(8, 0))

        # Right: plugin options above, results and log below
        right = ttk.PanedWindow(panes, orient="vertical")
        panes.add(right, weight=3)
        # Give the results most of the height once the window has its real size
        self.after(150, lambda: right.sashpos(0, 190))

        self.details, details_body = self._card(right, self.details_title)
        right.add(self.details, weight=1)
        self.options_canvas = tk.Canvas(details_body, highlightthickness=0, borderwidth=0, height=150)
        options_scroll = ttk.Scrollbar(
            details_body, orient="vertical", command=self.options_canvas.yview
        )
        self.options_canvas.configure(yscrollcommand=options_scroll.set)
        self.options_canvas.pack(side="left", fill="both", expand=True)
        options_scroll.pack(side="right", fill="y")
        self.options_frame = ttk.Frame(self.options_canvas)
        self._options_window = self.options_canvas.create_window(
            (0, 0), window=self.options_frame, anchor="nw"
        )
        self.options_frame.bind(
            "<Configure>",
            lambda _e: self.options_canvas.configure(
                scrollregion=self.options_canvas.bbox("all")
            ),
        )
        self.options_canvas.bind(
            "<Configure>",
            lambda e: self.options_canvas.itemconfigure(self._options_window, width=e.width),
        )

        card, output = self._card(right, "OUTPUT")
        right.add(card, weight=4)
        self.notebook = ttk.Notebook(output)
        self.notebook.pack(fill="both", expand=True)

        self.result_tab = ttk.Frame(self.notebook, padding=(0, 8, 0, 0))
        self.notebook.add(self.result_tab, text="Hasil")
        self.result_tab.rowconfigure(1, weight=1)
        self.result_tab.columnconfigure(0, weight=1)
        ttk.Label(self.result_tab, textvariable=self.result_var, style="Hint.TLabel").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 6)
        )
        self.table = ttk.Treeview(self.result_tab, show="headings", selectmode="extended")
        table_y = ttk.Scrollbar(self.result_tab, orient="vertical", command=self.table.yview)
        table_x = ttk.Scrollbar(self.result_tab, orient="horizontal", command=self.table.xview)
        self.table.configure(yscrollcommand=table_y.set, xscrollcommand=table_x.set)
        self.table.grid(row=1, column=0, sticky="nsew")
        table_y.grid(row=1, column=1, sticky="ns")
        table_x.grid(row=2, column=0, sticky="ew")
        self.table.bind("<<TreeviewSelect>>", lambda _e: self._show_row_detail())
        self.table.bind("<Control-c>", lambda _e: self._copy_rows())
        # The table shows one line per row; the full value of the selected row goes here
        self.detail = tk.Text(
            self.result_tab,
            height=5,
            wrap="word",
            font=self.mono,
            state="disabled",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        detail_y = ttk.Scrollbar(self.result_tab, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_y.set)
        self.detail.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        detail_y.grid(row=3, column=1, sticky="ns", pady=(8, 0))

        self.log_tab = ttk.Frame(self.notebook, padding=(0, 8, 0, 0))
        self.notebook.add(self.log_tab, text="Log")
        self.log_tab.rowconfigure(0, weight=1)
        self.log_tab.columnconfigure(0, weight=1)
        self.log = tk.Text(
            self.log_tab,
            wrap="none",
            font=self.mono,
            state="disabled",
            relief="flat",
            borderwidth=0,
            highlightthickness=1,
            padx=10,
            pady=8,
        )
        log_y = ttk.Scrollbar(self.log_tab, orient="vertical", command=self.log.yview)
        log_x = ttk.Scrollbar(self.log_tab, orient="horizontal", command=self.log.xview)
        self.log.configure(yscrollcommand=log_y.set, xscrollcommand=log_x.set)
        self.log.grid(row=0, column=0, sticky="nsew")
        log_y.grid(row=0, column=1, sticky="ns")
        log_x.grid(row=1, column=0, sticky="ew")

        self._apply_theme()
        self._show_plugin_details()

    def _set_progress(self, value: float) -> None:
        self.progress.configure(value=value)
        self.percent_var.set(f"{value:.0f}%" if value else "")

    # ----------------------------------------------------------- logging

    def write_log(self, text: str, tag: Optional[str] = None) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text, (tag,) if tag else ())
        self.log.see("end")
        self.log.configure(state="disabled")

    def clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    # ------------------------------------------------------ result table

    def _table_begin(self, job: Job) -> None:
        """Points the result table at a job whose column header has arrived."""
        assert job.columns is not None
        self.table_job = job
        self.table_shown = 0
        self.table_sort = (-1, False)
        self.table.delete(*self.table.get_children())
        ids = [f"c{i}" for i in range(len(job.columns))]
        self.table.configure(columns=ids, displaycolumns=ids)
        self.table_chars = []
        for i, name in enumerate(job.columns):
            self.table.heading(ids[i], text=name, anchor="w", command=lambda i=i: self._sort_table(i))
            self.table.column(
                ids[i],
                width=self.table_font.measure(name) + 28,
                minwidth=40,
                stretch=False,
                anchor="w",
            )
            self.table_chars.append(len(name))
        self._set_detail("Klik sebuah baris untuk melihat isinya secara lengkap.")
        self.notebook.select(self.result_tab)

    def _sync_table(self, job: Optional[Job] = None, flush: bool = False) -> None:
        """Copies rows the worker thread has parsed so far into the result table."""
        job = job or self.current
        if job and job.kind == "plugin" and job.columns is not None and job is not self.table_job:
            self._table_begin(job)
        job = self.table_job
        if not job or job.columns is None:
            return
        total = len(job.rows)
        end = min(total, MAX_TABLE_ROWS)
        if not flush:
            end = min(end, self.table_shown + TABLE_ROWS_PER_TICK)
        if end <= self.table_shown and not flush:
            return
        ids = self.table["columns"]
        for index in range(self.table_shown, end):
            depth, cells = job.rows[index]
            values = []
            for i in range(len(ids)):
                text = clean_cell(cells[i]) if i < len(cells) else ""
                if "\n" in text:
                    text = text.replace("\n", " ⏎ ")
                if len(text) > MAX_CELL_VIEW:
                    text = text[:MAX_CELL_VIEW] + " ..."
                if i == 0:
                    text = "    " * depth + text
                if len(text) > self.table_chars[i]:
                    self.table_chars[i] = len(text)
                    width = min(self.table_font.measure(text) + 28, MAX_COLUMN_PIXELS)
                    if width > int(self.table.column(ids[i], "width")):
                        self.table.column(ids[i], width=width)
                values.append(text)
            self.table.insert("", "end", iid=str(index), values=values, tags=("odd",) if index % 2 else ())
        self.table_shown = max(self.table_shown, end)
        note = ""
        if total > MAX_TABLE_ROWS:
            note = f" (menampilkan {MAX_TABLE_ROWS} pertama; lengkapnya ada di file output)"
        self.result_var.set(f"{job.plugin}  -  {total} baris{note}")

    def _sort_table(self, column: int) -> None:
        job = self.table_job
        if not job:
            return
        reverse = self.table_sort == (column, False)
        self.table_sort = (column, reverse)

        def key(iid: str) -> Tuple[int, Any]:
            cells = job.rows[int(iid)][1]
            return sort_key(cells[column] if column < len(cells) else "")

        for position, iid in enumerate(sorted(self.table.get_children(), key=key, reverse=reverse)):
            self.table.move(iid, "", position)
            self.table.item(iid, tags=("odd",) if position % 2 else ())

    def _set_detail(self, text: str) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)
        self.detail.configure(state="disabled")

    def _show_row_detail(self) -> None:
        job = self.table_job
        selection = self.table.selection()
        if not job or job.columns is None or not selection:
            return
        self._set_detail(format_record(job.columns, job.rows[int(selection[0])][1]))

    def _copy_rows(self) -> None:
        job = self.table_job
        selection = self.table.selection()
        if not job or job.columns is None or not selection:
            return
        lines = ["\t".join(job.columns)]
        lines += ["\t".join(clean_cell(cell).replace("\n", " ") for cell in job.rows[int(iid)][1]) for iid in selection]
        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))

    def _save_table(self, job: Job) -> bool:
        """Writes a parsed result to the job's output file in the chosen format."""
        assert job.outfile and job.columns is not None
        try:
            if job.outfile.suffix == ".csv":
                with open(job.outfile, "w", encoding="utf-8", newline="") as outfile:
                    writer = csv.writer(outfile)
                    writer.writerow(["TreeDepth"] + job.columns)
                    writer.writerows([str(depth)] + cells for depth, cells in job.rows)
            else:
                header = (
                    f"Plugin : {job.plugin}\n"
                    f"File   : {job.dump}\n"
                    f"Waktu  : {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n"
                    f"Baris  : {len(job.rows)}\n\n"
                )
                job.outfile.write_text(header + format_table(job.columns, job.rows), "utf-8")
        except OSError as excp:
            self.write_log(f"Gagal menulis file output: {excp}\n", "error")
            return False
        return True

    # ------------------------------------------------------- plugin list

    def _load_catalog_thread(self) -> None:
        try:
            catalog, failures = load_plugin_catalog()
            self.events.put(("catalog", catalog, failures))
        except Exception as excp:  # the framework itself could not be imported
            self.events.put(("catalog_error", f"{type(excp).__name__}: {excp}"))

    def selected_os(self) -> Optional[str]:
        for key, label in OS_LABELS.items():
            if label == self.os_var.get():
                return key
        return None

    def _refresh_plugins(self) -> None:
        self._update_badge()
        self.tree.delete(*self.tree.get_children())
        os_name = self.selected_os()
        if not os_name or not self.catalog:
            self._show_plugin_details()
            return
        needle = self.filter_var.get().strip().lower()
        groups = (
            (os_name, f"Plugin {OS_LABELS[os_name]}"),
            ("general", "Plugin umum (semua OS)"),
        )
        for group, title in groups:
            names = [
                name
                for name, info in self.catalog.items()
                if plugin_os(name) == group
                and (not needle or needle in name.lower() or needle in info["doc"].lower())
            ]
            if not names:
                continue
            parent = self.tree.insert(
                "",
                "end",
                iid=f"group:{group}",
                text=f"{title}  ({len(names)})",
                open=True,
                tags=("group",),
            )
            for name in names:
                label = name.split(".", 1)[1] if group != "general" else name
                self.tree.insert(
                    parent, "end", iid=name, text=label, values=(self.catalog[name]["doc"],)
                )
        self._show_plugin_details()

    def selected_plugins(self) -> List[str]:
        return [iid for iid in self.tree.selection() if iid in self.catalog]

    def _show_plugin_details(self) -> None:
        for child in self.options_frame.winfo_children():
            child.destroy()
        self.options_canvas.yview_moveto(0)
        selected = self.selected_plugins()
        wrap = 560

        if len(selected) != 1:
            self.details_title.set("OPSI PLUGIN")
            if len(selected) > 1:
                message = (
                    f"{len(selected)} plugin dipilih. Semuanya akan dijalankan berurutan, "
                    "masing-masing dengan opsi yang sudah Anda atur (atau default)."
                )
            elif not self.selected_os():
                message = (
                    "Pilih memory dump terlebih dahulu. Sistem operasinya akan dideteksi "
                    "otomatis dan daftar plugin yang sesuai akan muncul di sebelah kiri."
                )
            else:
                message = "Pilih plugin di sebelah kiri untuk melihat opsinya."
            ttk.Label(
                self.options_frame, text=message, wraplength=wrap, style="Hint.TLabel"
            ).grid(sticky="w")
            return

        name = selected[0]
        info = self.catalog[name]
        self.details_title.set(f"OPSI PLUGIN  ·  {name}")
        self.options_frame.columnconfigure(1, weight=1)
        ttk.Label(self.options_frame, text=info["doc"], wraplength=wrap).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 8)
        )

        variables = self.option_vars.setdefault(name, {})
        row = 1
        for option in info["options"]:
            flag = "--" + option["name"].replace("_", "-")
            label = flag + ("" if option["optional"] else "  (wajib)")
            if option["kind"] == "bool":
                var = variables.setdefault(option["name"], tk.BooleanVar(value=False))
                ttk.Checkbutton(self.options_frame, text=label, variable=var).grid(
                    row=row, column=0, sticky="w"
                )
            else:
                var = variables.setdefault(option["name"], tk.StringVar())
                ttk.Label(self.options_frame, text=label).grid(row=row, column=0, sticky="w")
                if option["kind"] == "choice":
                    widget: tk.Widget = ttk.Combobox(
                        self.options_frame,
                        textvariable=var,
                        values=[""] + option["choices"],
                        state="readonly",
                    )
                else:
                    widget = ttk.Entry(self.options_frame, textvariable=var)
                widget.grid(row=row, column=1, sticky="ew", padx=(8, 0))
                row += 1
            description = option["description"]
            if option["kind"] == "list":
                description += " (pisahkan beberapa nilai dengan spasi)"
            ttk.Label(
                self.options_frame,
                text=description,
                style="Hint.TLabel",
                wraplength=wrap - 180,
            ).grid(row=row, column=1, sticky="w", padx=(8, 0), pady=(0, 4))
            row += 1

        extra = self.extra_vars.setdefault(name, tk.StringVar())
        ttk.Label(self.options_frame, text="Argumen tambahan").grid(
            row=row, column=0, sticky="w", pady=(6, 0)
        )
        ttk.Entry(self.options_frame, textvariable=extra).grid(
            row=row, column=1, sticky="ew", padx=(8, 0), pady=(6, 0)
        )

    def _plugin_args(self, name: str) -> List[str]:
        """Builds the plugin's command line arguments from the option widgets."""
        args: List[str] = []
        variables = self.option_vars.get(name, {})
        for option in self.catalog[name]["options"]:
            var = variables.get(option["name"])
            if var is None:
                continue
            flag = "--" + option["name"].replace("_", "-")
            if option["kind"] == "bool":
                if var.get():
                    args.append(flag)
                continue
            value = str(var.get()).strip()
            if not value:
                continue
            if option["kind"] == "list":
                args += [flag] + shlex.split(value.replace(",", " "))
            else:
                args += [flag, value]
        extra = self.extra_vars.get(name)
        if extra and extra.get().strip():
            args += shlex.split(extra.get())
        return args

    # ------------------------------------------------------ file choices

    def choose_dump(self) -> None:
        path = filedialog.askopenfilename(
            title="Pilih memory dump",
            filetypes=[
                (
                    "Memory image",
                    "*.raw *.mem *.dmp *.vmem *.lime *.img *.bin *.dd *.elf *.core *.vmss *.vmsn *.sav",
                ),
                ("Semua file", "*"),
            ],
        )
        if path:
            self.dump_var.set(path)
            self.detect_os()

    def choose_outdir(self) -> None:
        path = filedialog.askdirectory(title="Pilih folder output")
        if path:
            self.outdir_var.set(path)
            self._outdir_auto = False

    def open_outdir(self) -> None:
        path = Path(normalize_path(self.outdir_var.get()) or DEFAULT_OUTPUT_ROOT)
        try:
            path.mkdir(parents=True, exist_ok=True)
            open_folder(path)
        except OSError as excp:
            messagebox.showerror("Gagal membuka folder", str(excp))

    def _checked_dump(self) -> Optional[str]:
        """Returns the memory image path, or None (after telling the user why)."""
        path = normalize_path(self.dump_var.get())
        problem = None
        if not path:
            problem = "Pilih file memory dump terlebih dahulu."
        elif not os.path.isfile(path):
            problem = f"File tidak ditemukan:\n{path}"
        elif os.path.getsize(path) == 0:
            problem = f"File kosong (0 byte):\n{path}"
        elif not os.access(path, os.R_OK):
            problem = f"File tidak bisa dibaca (izin ditolak):\n{path}"
        if problem:
            self.write_log(problem.replace("\n", " ") + "\n", "error")
            messagebox.showerror("Memory dump tidak bisa dibaca", problem)
            return None
        self.dump_var.set(path)
        return path

    # ------------------------------------------------------ OS detection

    def detect_os(self) -> None:
        if self.current:
            messagebox.showinfo(
                "Masih berjalan", "Tunggu proses yang berjalan selesai, atau tekan Stop."
            )
            return
        dump = self._checked_dump()
        if not dump:
            return
        if self._outdir_auto:
            self.outdir_var.set(str(DEFAULT_OUTPUT_ROOT / Path(dump).stem))
        self.detected_os = None
        self.detect_error = ""
        self.badge_state = "detecting"
        self.file_info_var.set(f"{Path(dump).name}  ·  {human_size(os.path.getsize(dump))}")
        self.os_var.set("")
        self._refresh_plugins()
        self.detect_var.set("Mendeteksi sistem operasi...")
        self.write_log(f"\n=== Deteksi OS: {dump} ===\n", "info")
        sniffed = sniff_os(dump)
        if sniffed:
            self._set_detected_os(*sniffed)
            return
        self.write_log(
            "Mencoba membaca sebagai Windows (windows.info)... Ini bisa beberapa menit; "
            "progres ada di kanan bawah.\n",
            "info",
        )
        self.notebook.select(self.log_tab)
        self._enqueue([Job("detect_windows", "windows.info.Info", dump, "csv")])

    def _finish_detect_windows(self, job: Job, returncode: int) -> None:
        if job.cancelled:
            self.detect_var.set("Deteksi dihentikan. Pilih OS secara manual bila perlu.")
            self.badge_state = "idle"
            self._update_badge()
            return
        if returncode == 0:
            self.write_log(format_table(job.columns or [], job.rows))
            self._set_detected_os("windows", "kernel Windows ditemukan")
            return
        self.detect_error = "".join(job.captured) + "\n".join(job.errors)
        self.write_log(
            "Bukan Windows (atau symbol tidak tersedia). Mencari banner Linux/Mac...\n", "info"
        )
        self._enqueue([Job("detect_banners", "banners.Banners", job.dump, "csv")])

    def _finish_detect_banners(self, job: Job, returncode: int) -> None:
        if job.cancelled:
            self.detect_var.set("Deteksi dihentikan. Pilih OS secara manual bila perlu.")
            self.badge_state = "idle"
            self._update_badge()
            return
        banners: List[str] = []
        text = "".join(job.captured)
        if returncode == 0 and job.columns and "Banner" in job.columns:
            column = job.columns.index("Banner")
            banners = [cells[column] for _depth, cells in job.rows if column < len(cells)]
        counts = collections.Counter()
        for banner in banners:
            if banner.startswith("Linux version"):
                counts["linux"] += 1
            elif banner.startswith("Darwin Kernel Version"):
                counts["mac"] += 1
        if counts:
            os_name = counts.most_common(1)[0][0]
            prefix = "Linux version" if os_name == "linux" else "Darwin Kernel Version"
            banner = next(b for b in banners if b.startswith(prefix))
            self.write_log(f"Banner: {banner}\n")
            self._set_detected_os(os_name, banner)
            return

        if returncode != 0:
            self.detect_error += "\n" + text + "\n".join(job.errors)
        self.detect_var.set("OS tidak terdeteksi - memory dump tidak bisa dibaca.")
        self.badge_state = "failed"
        self._update_badge()
        self.status_var.set("Deteksi OS gagal.")
        hint = explain_failure(self.detect_error, None) or ""
        self.write_log(
            "✖ Memory dump tidak bisa dibaca: bukan Windows, dan tidak ada banner "
            "Linux/Mac di dalamnya.\n",
            "error",
        )
        self.write_log(self.detect_error.strip() + "\n", "error")
        self.notebook.select(self.log_tab)
        detail = "\n".join(self.detect_error.strip().splitlines()[-18:])
        messagebox.showerror(
            "Memory dump tidak bisa dibaca",
            "Sistem operasi tidak dapat dideteksi dari file ini.\n\n"
            f"{hint}\n\nError dari Volatility:\n{detail}\n\n"
            "Jika Anda yakin file ini valid, pilih sistem operasi secara manual.",
        )

    def _set_detected_os(self, os_name: str, reason: str) -> None:
        self.detected_os = os_name
        self.badge_state = "idle"
        self.os_var.set(OS_LABELS[os_name])
        self._refresh_plugins()
        count = sum(1 for name in self.catalog if plugin_os(name) == os_name)
        short = reason if len(reason) <= 90 else reason[:87] + "..."
        self.detect_var.set(f"Terdeteksi: {OS_LABELS[os_name]} ({short})")
        self.status_var.set(f"{OS_LABELS[os_name]} terdeteksi - {count} plugin tersedia.")
        self.write_log(
            f"✔ Terdeteksi {OS_LABELS[os_name]}. {count} plugin {OS_LABELS[os_name]} "
            "ditampilkan di daftar.\n",
            "ok",
        )

    # ---------------------------------------------------- running plugins

    def _on_double_click(self, event: tk.Event) -> None:
        item = self.tree.identify_row(event.y)
        if item in self.catalog:
            self.tree.selection_set(item)
            self.run_selected()

    def run_selected(self) -> None:
        plugins = self.selected_plugins()
        if not plugins:
            messagebox.showinfo("Belum ada plugin", "Pilih minimal satu plugin dari daftar.")
            return
        dump = self._checked_dump()
        if not dump:
            return
        outdir = Path(normalize_path(self.outdir_var.get()) or DEFAULT_OUTPUT_ROOT / Path(dump).stem)
        try:
            outdir.mkdir(parents=True, exist_ok=True)
        except OSError as excp:
            messagebox.showerror("Folder output tidak bisa dibuat", str(excp))
            return
        self.outdir_var.set(str(outdir))

        renderer, extension = RENDERERS[self.format_var.get()]
        jobs = []
        for name in plugins:
            try:
                extra_args = self._plugin_args(name)
            except ValueError as excp:  # unbalanced quotes
                messagebox.showerror("Opsi tidak valid", f"{name}: {excp}")
                return
            # Impatient double-clicks should not run the same thing several times
            pending = [self.current] if self.current else []
            if any(
                (job.plugin, job.dump, job.renderer, job.extra_args)
                == (name, dump, renderer, extra_args)
                for job in pending + list(self.jobs)
            ):
                self.write_log(f"{name} sudah berjalan / ada di antrean.\n", "info")
                continue
            stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
            jobs.append(
                Job(
                    "plugin",
                    name,
                    dump,
                    renderer,
                    extra_args,
                    outfile=outdir / f"{name}_{stamp}{extension}",
                    dump_dir=outdir / f"{name}_{stamp}_files",
                )
            )
        if self.current and jobs:
            names = ", ".join(job.plugin for job in jobs)
            waiting = (
                "deteksi OS" if self.current.kind != "plugin" else self.current.plugin
            )
            self.write_log(
                f"Antrean: {names} akan dijalankan setelah {waiting} selesai.\n", "info"
            )
        self._enqueue(jobs)

    def _enqueue(self, jobs: List[Job]) -> None:
        self.jobs.extend(jobs)
        self.batch_total += sum(1 for job in jobs if job.kind == "plugin")
        if not self.current:
            self._start_next()

    def _start_next(self) -> None:
        if not self.jobs:
            self.batch_total = 0
            self.stop_button.configure(state="disabled")
            self._set_progress(0)
            return
        job = self.jobs.popleft()
        self.current = job
        self.stop_button.configure(state="normal")
        self._set_progress(0)

        if job.kind == "plugin":
            done = self.batch_total - sum(1 for queued in self.jobs if queued.kind == "plugin")
            self.write_log(f"\n=== [{done}/{self.batch_total}] {job.plugin} ===\n", "info")
            self.write_log("$ " + " ".join(shlex.quote(part) for part in job.command()[2:]) + "\n", "info")
            self.write_log(
                "Sedang berjalan... progres ada di kanan bawah. Pertama kali pada sebuah "
                "dump bisa beberapa menit karena symbol harus disiapkan.\n",
                "info",
            )
            self.status_var.set(f"Menjalankan {job.plugin}...")
            if not job.tabular:
                self.notebook.select(self.log_tab)

        env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUNBUFFERED="1")
        try:
            if job.dump_dir:
                job.dump_dir.mkdir(parents=True, exist_ok=True)
            self.proc = subprocess.Popen(
                job.command(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,
                cwd=str(BASE_DIR),
                env=env,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except OSError as excp:
            job.errors.append(f"Tidak bisa menjalankan vol.py: {excp}")
            self.events.put(("done", job, -1))
            return
        threading.Thread(target=self._pump, args=(job, self.proc), daemon=True).start()

    def _pump(self, job: Job, proc: subprocess.Popen) -> None:
        """Worker thread: collects the process output for the GUI."""
        stderr_thread = threading.Thread(
            target=self._pump_stderr, args=(job, proc), daemon=True
        )
        stderr_thread.start()
        try:
            if job.tabular:
                self._pump_table(job, proc)
            else:
                self._pump_raw(job, proc)
        except (OSError, csv.Error) as excp:
            job.errors.append(f"Gagal memproses output: {excp}")
            proc.kill()
        stderr_thread.join()
        self.events.put(("done", job, proc.wait()))

    def _pump_table(self, job: Job, proc: subprocess.Popen) -> None:
        """Parses a CSV rendering into job.columns and job.rows as it arrives."""
        stream = io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace", newline="")
        # Anything ahead of the CSV header is a message, not a result: when a
        # plugin cannot run, Volatility explains why on stdout.
        for line in stream:
            if line.startswith("TreeDepth"):
                job.columns = next(csv.reader([line], escapechar="\\"))[1:]
                break
            job.captured.append(line)
        if job.columns is None:
            return
        for record in csv.reader(stream, escapechar="\\"):
            if not record:
                continue
            try:
                depth = int(record[0])
            except ValueError:
                job.captured.append(",".join(record) + "\n")
                continue
            job.rows.append((depth, record[1:]))

    def _pump_raw(self, job: Job, proc: subprocess.Popen) -> None:
        """Streams a rendering Volatility formats itself straight into the output file."""
        assert job.outfile
        lines = 0
        with open(job.outfile, "wb") as outfile:
            for raw in iter(proc.stdout.readline, b""):
                lines += 1
                outfile.write(raw)
                if lines <= MAX_VIEW_LINES:
                    self.events.put(("stdout", job, raw.decode("utf-8", "replace")))
                elif lines == MAX_VIEW_LINES + 1:
                    self.events.put(("truncated", job))

    def _pump_stderr(self, job: Job, proc: subprocess.Popen) -> None:
        # Progress updates are separated by carriage returns, real messages by newlines
        pending = b""
        last_progress = 0.0
        while True:
            chunk = proc.stderr.read1(4096)
            if not chunk:
                break
            parts = re.split(rb"[\r\n]", pending + chunk)
            pending = parts.pop()
            for part in parts:
                last_progress = self._handle_stderr(job, part, last_progress)
        self._handle_stderr(job, pending, 0.0)

    def _handle_stderr(self, job: Job, raw: bytes, last_progress: float) -> float:
        line = raw.decode("utf-8", "replace").rstrip()
        if not line.strip():
            return last_progress
        match = PROGRESS_RE.match(line.strip())
        if match:
            now = time.monotonic()
            if now - last_progress >= PROGRESS_INTERVAL:
                self.events.put(("progress", job, float(match.group(1)), match.group(2).strip()))
                return now
            return last_progress
        job.errors.append(line)
        self.events.put(("stderr", job, line + "\n"))
        return last_progress

    def stop(self) -> None:
        if not self.current:
            return
        skipped = len(self.jobs)
        self.jobs.clear()
        self.current.cancelled = True
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        note = f" ({skipped} plugin di antrean dibatalkan)" if skipped else ""
        self.write_log(f"Menghentikan proses...{note}\n", "stderr")

    def _finish_plugin(self, job: Job, returncode: int) -> None:
        assert job.outfile and job.dump_dir
        dumped = 0
        if job.dump_dir.is_dir():
            dumped = sum(1 for _ in job.dump_dir.iterdir())
            if not dumped:
                job.dump_dir.rmdir()

        # A table is written once the run is over; whatever rows arrived before
        # a failure or a stop are still worth keeping.
        saved = False
        if job.tabular:
            self._sync_table(job, flush=True)
            complete = returncode == 0 and not job.cancelled
            if job.columns is not None and (job.rows or complete):
                saved = self._save_table(job)
        rows = f"{len(job.rows)} baris. " if job.tabular else ""

        if job.cancelled:
            if not job.tabular and job.outfile.exists() and job.outfile.stat().st_size == 0:
                job.outfile.unlink()
            self.write_log(f"■ {job.plugin} dihentikan.\n", "stderr")
            if saved:
                self.write_log(f"  Hasil sebagian ({rows.strip()}) disimpan: {job.outfile}\n", "stderr")
            self.status_var.set("Dihentikan.")
            return

        if returncode == 0:
            self.write_log(f"✔ Selesai. {rows}Output: {job.outfile}\n", "ok")
            if dumped:
                self.write_log(f"✔ {dumped} file hasil dump: {job.dump_dir}\n", "ok")
            self.status_var.set(f"{job.plugin} selesai. {rows}")
            return

        # On failure Volatility prints the reason on stdout.  For a rendering it
        # formats itself that text landed in the output file, which is then an
        # error report rather than a result: keep it as a log instead.
        error_path = job.outfile.with_name(job.outfile.stem + ".error.log")
        produced = "".join(job.captured)
        try:
            if not job.tabular and job.outfile.exists():
                produced = job.outfile.read_text("utf-8", "replace")
                job.outfile.unlink()
            error_path.write_text(
                f"Plugin : {job.plugin}\nFile   : {job.dump}\nExit   : {returncode}\n\n"
                f"{produced}\n{os.linesep.join(job.errors)}\n",
                "utf-8",
            )
        except OSError as excp:
            self.write_log(f"Gagal menyimpan log error: {excp}\n", "error")
        if job.tabular and produced.strip():
            self.write_log(produced.strip() + "\n", "stderr")
        self.write_log(f"✖ {job.plugin} gagal (exit code {returncode}).\n", "error")
        hint = explain_failure(produced + "\n".join(job.errors), self.selected_os())
        if hint:
            self.write_log(hint + "\n", "error")
        self.write_log(f"  Log error: {error_path}\n", "error")
        if saved:
            self.write_log(f"  Hasil sebagian ({rows.strip()}) disimpan: {job.outfile}\n", "error")
        self.status_var.set(f"{job.plugin} gagal - lihat log.")
        self.notebook.select(self.log_tab)

    # --------------------------------------------------------- event loop

    def _poll_events(self) -> None:
        for _ in range(400):
            try:
                event = self.events.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
        self._sync_table()
        self.after(60, self._poll_events)

    def _handle_event(self, event: Tuple[Any, ...]) -> None:
        kind = event[0]
        if kind == "catalog":
            self.catalog = event[1]
            for failure in event[2]:
                self.write_log(f"Plugin gagal dimuat: {failure}\n", "stderr")
            self.status_var.set(f"{len(self.catalog)} plugin dimuat. Pilih memory dump untuk mulai.")
            self._refresh_plugins()
            return
        if kind == "catalog_error":
            self.status_var.set("Volatility 3 gagal dimuat.")
            self.write_log(f"Volatility 3 gagal dimuat: {event[1]}\n", "error")
            messagebox.showerror("Volatility 3 gagal dimuat", event[1])
            return

        job = event[1]
        if job is not self.current:
            return
        if kind == "stdout":
            self.write_log(event[2])
        elif kind == "stderr":
            if job.kind == "plugin":
                self.write_log(event[2], "stderr")
        elif kind == "truncated":
            self.write_log(
                f"... tampilan dipotong di {MAX_VIEW_LINES} baris; hasil lengkap ada di file output ...\n",
                "info",
            )
        elif kind == "progress":
            self._set_progress(event[2])
            self.status_var.set(f"{job.plugin}: {event[3] or 'memproses'} ({event[2]:.0f}%)")
        elif kind == "done":
            self.proc = None
            self.current = None
            if job.kind == "plugin":
                self._finish_plugin(job, event[2])
            elif job.kind == "detect_windows":
                self._finish_detect_windows(job, event[2])
            else:
                self._finish_detect_banners(job, event[2])
            if not self.current:
                self._start_next()

    def _on_close(self) -> None:
        if self.current and not messagebox.askyesno(
            "Keluar", "Masih ada proses yang berjalan. Hentikan dan keluar?"
        ):
            return
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
        self.destroy()


def main() -> None:
    if not VOL_PY.is_file():
        sys.exit(f"vol.py tidak ditemukan di {BASE_DIR}")
    VolatilityGUI().mainloop()


if __name__ == "__main__":
    main()
