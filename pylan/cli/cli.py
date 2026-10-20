import click

from pylan.cli.scan import scan
from pylan.cli.receive import receive


@click.group()
def cli():
    """PyLan - Local network file transfer tool."""
    pass


cli.add_command(scan)
cli.add_command(receive)
