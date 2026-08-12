# Create this file first — all scripts need it
# Path: scripts\utils\logger.py

import logging
import sys
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama for Windows color support
init(autoreset=True)

def get_logger(name: str, log_file: str = None) -> logging.Logger:
    """
    Create a logger that works correctly on Windows.
    Handles Windows encoding issues automatically.
    """
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    # ── Console handler with Windows UTF-8 fix ───────────────────
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Windows-safe formatter (no special unicode chars)
    formatter = logging.Formatter(
        fmt    = '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt= '%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # ── File handler ─────────────────────────────────────────────
    if log_file:
        try:
            from config import BASE_DIR
            logs_dir = Path(BASE_DIR) / 'logs'
        except Exception:
            logs_dir = Path(__file__).resolve().parent.parent / 'logs'
        logs_dir.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(
            logs_dir / log_file,
            encoding='utf-8'    # Critical for Windows
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def print_section(title: str):
    """Print a visible section header"""
    print(f'\n{Fore.CYAN}{"=" * 55}')
    print(f'{Fore.CYAN}{title}')
    print(f'{Fore.CYAN}{"=" * 55}{Style.RESET_ALL}')


def print_success(message: str):
    print(f'{Fore.GREEN}✓ {message}{Style.RESET_ALL}')


def print_warning(message: str):
    print(f'{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}')


def print_error(message: str):
    print(f'{Fore.RED}✗ {message}{Style.RESET_ALL}')


def print_info(message: str):
    print(f'{Fore.WHITE}  {message}{Style.RESET_ALL}')