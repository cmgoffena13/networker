from typer import Typer

from src.logging_conf import setup_logging

app = Typer(help="Networker CLI - Interact with your local network")


def main() -> None:
    setup_logging()
    app()


if __name__ == "__main__":
    main()
