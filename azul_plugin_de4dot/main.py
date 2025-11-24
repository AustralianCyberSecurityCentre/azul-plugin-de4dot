"""Dotnet deobfuscator based on de4dot, used to be part of netalyser."""

import logging
import os
import re
import subprocess  # noqa # nosec: B404
import tempfile
import traceback

import pefile
from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)

logger = logging.getLogger(__name__)


class De4dot(BinaryPlugin):
    """De4dot .NET deobfuscator plugin."""

    VERSION = "2025.11.24"  # Note de4dot is about a year old https://github.com/kant2002/de4dot (net8 from source)
    FEATURES = [Feature("obfuscator", desc="Name of obfuscator detected by de4dot", type=FeatureType.String)]
    SETTINGS = add_settings(
        filter_data_types={
            "content": [
                "executable/windows/dll32",
                "executable/windows/dll64",
                "executable/windows/pe",
                "executable/windows/pe32",
                "executable/windows/pe64",
                "executable/dll32",
                "executable/pe32",
            ]
        },
        filter_max_content_size=(int, 10 * 1024 * 1024),
        subprocess_timeout=(int, 120),  # Seconds
    )

    def execute(self, job: Job):
        """Run the plugin."""
        data = job.get_data()
        in_file_path = data.get_filepath()
        # check if it's really .NET
        try:
            with pefile.PE(in_file_path, fast_load=True) as pe:
                if (
                    len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < 15
                    or pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress == 0
                ):
                    return State(State.Label.OPT_OUT, "Not a .NET assembly")
        except pefile.PEFormatError:
            return State(
                State.Label.ERROR_EXCEPTION, failure_name="Error while parsing PE", message=traceback.format_exc()
            )

        with tempfile.NamedTemporaryFile() as deob_out_file:
            de4dot_exe = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "de4dot_20251124_netcore8", "linux-x64", "de4dot.dll"
            )
            command = [
                "dotnet",
                de4dot_exe,
                "-f",
                os.path.join(in_file_path),
                "-o",
                os.path.join(deob_out_file.name),
            ]

            try:
                res: subprocess.CompletedProcess = subprocess.run(  # nosec: B603
                    args=command,
                    stdin=None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=self.cfg.subprocess_timeout,
                    encoding="utf8",
                )
            except OSError as e:
                logger.error("%s: %s for %s" % (e.__class__.__name__, e.args, job.id))
                return State(
                    State.Label.ERROR_EXCEPTION,
                    "%s executing de4dot" % e.__class__.__name__,
                    message=traceback.format_exc(),
                )
            except subprocess.TimeoutExpired:
                # subprocess.run takes care of terminating the child on timeout
                logger.error("Timed out running de4dot on %s" % job.id)
                return State(State.Label.ERROR_EXCEPTION, "Timeout executing de4dot", message=traceback.format_exc())

            # Handle case that de4dot can detect the file is obfuscated but doesn't know how to reverse it.
            if "Detected Unknown Obfuscator" in res.stdout:
                return State(State.Label.COMPLETED_EMPTY, message="De4dot does not know how to deobfuscate this file.")

            if res.returncode != 0:
                return State(
                    State.Label.ERROR_EXCEPTION, message=f"Unexpected error occurred when deobfuscating {res.stderr}"
                )

            deob_file_valid = False
            deob_out_file.seek(0)
            deob_file_size = os.stat(deob_out_file.name).st_size
            if deob_file_size > 0 and deob_file_size < 2 * self.cfg.filter_max_content_size:
                # Don't add deob file if it's got no content or is twice the size of the original input.
                deob_file_valid = False

            # Process stdout/results
            if re.search(r"WARNING: The file isn't a \.NET PE file", res.stdout):
                self.is_malformed("Malformed dotnet file (may be version > 3.1).")
                return

            multi_obs = re.search(r"More than one obfuscator detected..(.+)Detected", res.stdout, re.DOTALL)
            if multi_obs:
                # multiple detected, and nothing was done probably
                if deob_file_valid:
                    self.add_child_with_data_file({"rel_action": "deobfuscated"}, deob_out_file)
                self.add_feature_values("obfuscator", re.findall(r"\s*([^(]+)\s+\(use: [^)]+\)", multi_obs.group(1)))
                return State(State.Label.COMPLETED)

            main_obfs = re.search(r"Detected ([^(]+) \(", res.stdout)
            if not main_obfs:
                raise AssertionError(
                    'de4dot executable returned unexpected output - could not find "detected" message'
                    f"\n -----\n{res.stdout}"
                )

            # only single deobfuscator used
            if main_obfs.group(1) == "Unknown Obfuscator":
                # Ignore the output if an 'Unknown Obfuscator' is detected,
                # because it reports this for every file
                return State(State.Label.COMPLETED)

            # OK, it appears to be a valid obfuscator detection
            if deob_file_valid:
                self.add_child_with_data_file({"rel_action": "deobfuscated"}, deob_out_file)
            self.add_feature_values("obfuscator", main_obfs.group(1))
            return State(State.Label.COMPLETED)


def main():
    """Plugin cmdline entry point."""
    cmdline_run(plugin=De4dot)


if __name__ == "__main__":
    main()
