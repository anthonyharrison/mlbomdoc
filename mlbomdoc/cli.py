# Copyright (C) 2024 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.parser import SBOMParser

import mlbomdoc.generator as generator
from mlbomdoc.version import VERSION

# CLI processing


def main(argv=None):
    argv = argv or sys.argv
    app_name = "mlbomdoc"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            MLBOMdoc generates documentation for a MLBOM.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "-i",
        "--input-file",
        action="store",
        default="",
        help="Name of MLBOM file",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )

    # Add format option
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        help="Output format (default: output to console)",
        choices=["console", "json", "markdown", "pdf"],
        default="console",
    )

    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "input_file": "",
        "output_file": "",
        "debug": False,
        "format": "console",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    input_file = args["input_file"]

    if input_file == "":
        print("[ERROR] MLBOM name must be specified.")
        return -1

    if args["format"] != "console" and args["output_file"] == "":
        print("[ERROR] Output filename must be specified.")
        return -1

    if args["debug"]:
        print("Input file", args["input_file"])
        print("Output file", args["output_file"])

    sbom_parser = SBOMParser()
    # Load SBOM - will autodetect SBOM type
    try:
        sbom_parser.parse_file(input_file)

        generator.generate_document(
            args["format"], sbom_parser, input_file, args["output_file"]
        )

    except FileNotFoundError:
        print(f"{input_file} not found")

    return 0


if __name__ == "__main__":
    sys.exit(main())
