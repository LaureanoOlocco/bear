#!/usr/bin/env python3
"""Terminal colors and visual helpers for BEAR."""

import logging


class BearColors:
    """Enhanced color palette for terminal output."""

    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'

    MATRIX_GREEN = '\033[38;5;46m'
    NEON_BLUE = '\033[38;5;51m'
    ELECTRIC_PURPLE = '\033[38;5;129m'
    CYBER_ORANGE = '\033[38;5;208m'
    HACKER_RED = '\033[38;5;196m'
    TERMINAL_GRAY = '\033[38;5;240m'
    BRIGHT_WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    BLOOD_RED = '\033[38;5;124m'
    CRIMSON = '\033[38;5;160m'
    DARK_RED = '\033[38;5;88m'
    FIRE_RED = '\033[38;5;202m'
    RUBY = '\033[38;5;161m'

    SUCCESS = '\033[38;5;46m'
    WARNING = '\033[38;5;208m'
    ERROR = '\033[38;5;196m'
    CRITICAL = '\033[48;5;196m\033[38;5;15m\033[1m'
    INFO = '\033[38;5;51m'
    DEBUG = '\033[38;5;240m'

    TOOL_RUNNING = '\033[38;5;46m\033[5m'
    TOOL_SUCCESS = '\033[38;5;46m\033[1m'
    TOOL_FAILED = '\033[38;5;196m\033[1m'


Colors = BearColors


class ColoredFormatter(logging.Formatter):
    """Logging formatter that colors records by severity."""

    COLORS = {
        'DEBUG': BearColors.DEBUG,
        'INFO': BearColors.SUCCESS,
        'WARNING': BearColors.WARNING,
        'ERROR': BearColors.ERROR,
        'CRITICAL': BearColors.CRITICAL,
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, BearColors.BRIGHT_WHITE)
        record.msg = f"{color}{record.msg}{BearColors.RESET}"
        return super().format(record)


class ModernVisualEngine:
    """Visual output formatting for terminal display."""

    COLORS = {
        'MATRIX_GREEN': '\033[38;5;46m',
        'NEON_BLUE': '\033[38;5;51m',
        'ELECTRIC_PURPLE': '\033[38;5;129m',
        'CYBER_ORANGE': '\033[38;5;208m',
        'HACKER_RED': '\033[38;5;196m',
        'TERMINAL_GRAY': '\033[38;5;240m',
        'BRIGHT_WHITE': '\033[97m',
        'RESET': '\033[0m',
        'BOLD': '\033[1m',
        'BLOOD_RED': '\033[38;5;124m',
        'CRIMSON': '\033[38;5;160m',
    }

    PROGRESS_STYLES = {
        'dots': ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'],
    }

    @staticmethod
    def create_banner(version: str) -> str:
        """Create the BEAR banner."""
        accent = ModernVisualEngine.COLORS['HACKER_RED']
        reset = ModernVisualEngine.COLORS['RESET']
        bold = ModernVisualEngine.COLORS['BOLD']
        return f"""
{accent}{bold}
██████╗ ███████╗ █████╗ ██████╗
██╔══██╗██╔════╝██╔══██╗██╔══██╗
██████╔╝█████╗  ███████║██████╔╝
██╔══██╗██╔══╝  ██╔══██║██╔══██╗
██████╔╝███████╗██║  ██║██║  ██║
╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝
{reset}
{accent}┌─────────────────────────────────────────────────────────────────────────────┐
│  {ModernVisualEngine.COLORS['BRIGHT_WHITE']}Binary Exploitation & Automated Reversing{accent}                 v{version}           │
│  {ModernVisualEngine.COLORS['CYBER_ORANGE']}Debuggers | Disassemblers | Exploit Development{accent}                            │
└─────────────────────────────────────────────────────────────────────────────┘{reset}
"""

    @staticmethod
    def render_progress_bar(progress: float, width: int = 40, style: str = 'cyber',
                            label: str = "", eta: float = 0, speed: str = "") -> str:
        """Render a progress bar."""
        progress = max(0.0, min(1.0, progress))
        filled_width = int(width * progress)
        empty_width = width - filled_width
        bar = '█' * filled_width + '░' * empty_width
        percentage = f"{progress * 100:.1f}%"
        extra_info = f" ETA: {eta:.1f}s" if eta > 0 else ""
        if speed:
            extra_info += f" Speed: {speed}"
        if label:
            return f"{label}: [{bar}] {percentage}{extra_info}"
        return f"[{bar}] {percentage}{extra_info}"

    @staticmethod
    def format_tool_status(tool_name: str, status: str, target: str = "", progress: float = 0.0) -> str:
        """Format tool execution status."""
        color = ModernVisualEngine.COLORS['MATRIX_GREEN'] if status == 'SUCCESS' else ModernVisualEngine.COLORS['HACKER_RED']
        return f"{color}🔧 {tool_name.upper()}{ModernVisualEngine.COLORS['RESET']} | {status} | {target}"
