#!/usr/bin/env python
# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   This module generates a hex value that can be passed to other examples (GetUserSPNs, etc.) to set Kerberos options.
#   Both parsing of command line arguments in the form of a comma separated integer list, and an interactive menu are provided.
#   The logic in here simply sets bits in a 32-bit integer based on the value of the option, then converts that to hex.
#   This is based off of the code written by @ben0xa for Orpheus: https://github.com/trustedsec/orpheus.
#
# Author:
#   p0rtL (@p0rtl6)
#

import sys
from impacket.krb5 import constants

selectedOptions = {enum.value: False for enum in constants.KDCOptions}


def print_help():
    print("Generate Kerberos Options Script")
    print("")
    print("Run without any arguments to open the interactive menu")
    print("OR")
    print("Provide a comma separated list of integers between 0-31 (e.g. 1,8,15,27)")
    print("")


def print_options():
    print("")

    output = list()

    for option in sorted(constants.KDCOptions, key=lambda variant: variant.value):
        output.append(
            "({}) {} [{}]".format(
                option.value,
                option.name,
                "On" if selectedOptions[option.value] else "Off",
            )
        )

    output.append("")  # Pad to even number of elements

    halfPoint = len(output) // 2
    firstHalf = output[:halfPoint]
    secondHalf = output[halfPoint:]

    for left, right in zip(firstHalf, secondHalf):
        print("{:30s}{}".format(left, right))

    print("")


def print_hex(simple=False):
    binOptions = "".join("1" if selectedOptions.get(i, False) else "0" for i in range(32))
    hexOptions = hex(int(binOptions, 2))

    if simple:
        print(hexOptions)
    else:
        print("Generated Hex [{}]".format(hexOptions))
        print("")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        strippedArg = sys.argv[1].lstrip("-")
        if strippedArg == "help" or strippedArg == "h":
            print_help()
            sys.exit()

    # Take command line list of options
    if len(sys.argv) > 1:
        try:
            argInputString = sys.argv[1]
            argInputList = [int(number) for number in argInputString.split(",")]
            for optionNumber in argInputList:
                if optionNumber < 0 or optionNumber > 31:
                    raise ValueError("Number is not between 0-31")

                selectedOptions[optionNumber] = True

            print_hex(simple=True)
            sys.exit()
        except Exception as _:
            print("[ERROR] Cannot parse argument list, make sure you are providing a comma seperated list of integers between 0-31.")

    # If options are not provided on the command line, prompt for them in a menu
    while True:
        print_options()
        print_hex()

        userInput = input("Enter a number to toggle the corresponding option (or 'exit' to exit): ")
        if userInput.lower() == "exit":
            break

        try:
            userInputInteger = int(userInput)
            if userInputInteger < 0 or userInputInteger > 31:
                raise ValueError("Number is not between 0-31")

            selectedOptions[userInputInteger] = not selectedOptions[userInputInteger]
        except:
            print("[ERROR] Please enter a valid number from 0-31")
