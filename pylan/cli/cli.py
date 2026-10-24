import click

from pylan.cli.scan import scan
from pylan.cli.receive import receive
from pylan.cli.send import send


@click.group()
def cli() -> None:
    """PyLan - Local network file transfer tool."""
    pass


cli.add_command(scan)
cli.add_command(receive)
cli.add_command(send)
