#!/usr/bin/env python3

"""
A cmd2 console that integrates all impacket-tools into one.

Vision is an metasploit-style console that allows you to set inputs then load impacket modules for AD red teaming.

"""
import cmd2
from cmd2 import (
    Color,
    stylize,
)
from rich.style import Style
import SearchModules
import sys
import argparse
import json
import PrintTable

cmd2.Cmd.DEFAULT_CATEGORY = "ADAConsole Commands"

BANNER = """
========================================================================
   Activate Directory Attacker Console (ADAConsole) v0.1.0
========================================================================
Type `help` for commands
"""

# Command categories
MODULE_USAGE = "Explore available modules"


class adaConsole(cmd2.Cmd):
    """Basic app to get started"""

    def __init__(self):
        # Initialise cmd2
        super().__init__(
            auto_suggest=True,
            persistent_history_file="cmd2_history.dat",
        )

        # Stash modules data
        # Generated using Claude AI - asked it to parse impacket repo to extract the required info
        # Long term need to find a better module storage solution - static json won't last
        with open("./modules.json", 'r', encoding='utf-8') as file:
            data = json.load(file)

        self.modules = data["modules"]

        self.intro = (
                stylize(
                    BANNER,
                    style=Style(color=Color.GREEN1, bgcolor=Color.GRAY0, bold=True),
                )
        )

        self.hidden_commands += [
            "alias", "edit", "history", "macro", "run_pyscript",
            "run_script", "shell", "shortcuts", "set"
        ]

        # Show this as the prompt when asking for input
        self.prompt = "adaconsole> "


    @cmd2.with_category(MODULE_USAGE)
    def do_list(self, args):        # <-- do_ prefix, and needs `arg` param
        """List all available modules."""
        self.poutput(PrintTable.createTable(self.modules))

    moduleSearchParser = cmd2.Cmd2ArgumentParser(description="Search for modules")
    moduleSearchParser.add_argument("search_terms", help="search terms to search")

    # TODO refine arguments, e.g. add function to search just name or just description
    @cmd2.with_category(MODULE_USAGE)
    @cmd2.with_argparser(moduleSearchParser)
    def do_search(self, args: argparse.Namespace):
        """Search modules"""

        resultsTable, numResults = SearchModules.searchModule(self.modules, args.search_terms)

        numResultsString = "{} Results Found:\n".format(numResults) if numResults else "No Results Found"

        self.poutput(numResultsString)
        self.poutput(PrintTable.createTable(resultsTable))


if __name__ == '__main__':
    app = adaConsole()
    sys.exit(app.cmdloop())
