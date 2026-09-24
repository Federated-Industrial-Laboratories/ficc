#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Export the node response schema. Input: output path. Exit: 0 on success.
"""Write the versioned helper contract from its validation model."""

import argparse
import json
from pathlib import Path

from ficc.schema import Sample


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.write_text(json.dumps(Sample.model_json_schema(), indent=2) + "\n")


if __name__ == "__main__":
    main()
