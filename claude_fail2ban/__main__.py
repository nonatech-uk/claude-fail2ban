"""Allow `python -m claude_fail2ban` to invoke the CLI."""

from .cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())
