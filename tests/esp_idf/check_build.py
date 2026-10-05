# Copyright 2026 Sendspin Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Checks that a finished build pulled in exactly the codecs its sdkconfig enables.

Run from this project directory after `idf.py build`:
`python check_build.py --flac on|off --opus on|off`.
Each codec must be resolved in dependencies.lock, fetched into managed_components, required by
the sendspin-cpp component, and linked into the app image if and only if it is enabled.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flac", choices=("on", "off"), required=True)
    parser.add_argument("--opus", choices=("on", "off"), required=True)
    args = parser.parse_args()

    description = json.loads((PROJECT_DIR / "build/project_description.json").read_text())
    component = description["build_component_info"]["sendspin-cpp"]
    for key in ("reqs", "priv_reqs", "managed_priv_reqs"):
        print(f"sendspin-cpp {key}: {' '.join(component[key])}")

    nm = description["monitor_toolprefix"] + "nm"
    elf = Path(description["build_dir"]) / description["app_elf"]
    symbols = subprocess.run(
        [nm, "--defined-only", "--demangle", "--format=just-symbols", str(elf)],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    lock = (PROJECT_DIR / "dependencies.lock").read_text()

    # (codec, enabled, predicate matching one of its linked symbols)
    codecs = (
        ("micro-flac", args.flac == "on", lambda s: s.startswith("micro_flac::")),
        ("micro-opus", args.opus == "on", lambda s: s.startswith("opus_")),
    )
    failures = []
    for codec, enabled, is_codec_symbol in codecs:
        found = {
            "in dependencies.lock": f"esphome/{codec}:" in lock,
            "in managed_components": (PROJECT_DIR / f"managed_components/esphome__{codec}").is_dir(),
            "a sendspin-cpp requirement": any(
                r == codec or r.endswith(f"__{codec}") for r in component["managed_priv_reqs"]
            ),
            "linked": any(is_codec_symbol(s) for s in symbols),
        }
        for what, present in found.items():
            if present != enabled:
                failures.append(f"{codec} is {'not ' if enabled else ''}{what}")

    for failure in failures:
        print(f"FAIL: {failure}")
    if not failures:
        print("OK: codec dependencies match the configuration")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
