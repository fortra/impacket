
from rich.table import Table

# Create a nice table from selected modules
def createTable(modules):

    if modules is None:
        return None

    # Initialise table
    table = Table(title="Module List", show_header=True, header_style='bold blue', show_lines=True)

    table.add_column("#")
    table.add_column("Module Name")
    table.add_column("Module Description")

    for module in modules:
        table.add_row(module["id"], module["name"], module["description"])

    return table
