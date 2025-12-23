from rich.console import Console
from rich.theme import Theme

matrix_theme = Theme(
    {
        "logging.level.debug": "bold green",
        "logging.level.info": "bold green",
        "logging.level.warning": "bold yellow",
        "logging.level.error": "bold red",
        "logging.level.critical": "bold red",
        "log.message": "green",
    }
)
console = Console(theme=matrix_theme)


def echo(message: str, **kwargs):
    console.print(message, style="green", **kwargs)
