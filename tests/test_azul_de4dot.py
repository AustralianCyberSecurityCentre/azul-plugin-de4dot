from azul_runner import FV, Event, JobResult, State, test_template

from azul_plugin_de4dot.main import De4dot


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = De4dot

    def test_not_dotnet(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "702e31ed1537c279459a255460f12f0f2863f973e121cd9194957f4f3e7b0994",
                        "Benign Windows 32EXE, python library executable python_mcp.exe",
                    ),
                )
            ]
        )
        self.assertJobResult(result, JobResult(state=State(State.Label.OPT_OUT, failure_name="Not a .NET assembly")))

    def test_benign_dotnet(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "9c44230c8e01057143430213fc271fed07a4398b54039980156225d81c184c6c",
                        "Benign Windows 32EXE, .NET based.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            # No features should be set if no known obfuscator is detected
            JobResult(
                state=State(State.Label.COMPLETED_EMPTY, message="De4dot does not know how to deobfuscate this file.")
            ),
        )

    def test_obfus_dotnet(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "e05ecc14c86d96d64495434a7e34f35588538ae2e6da20c2dacc4a97001c35df", "Malicious Windows 32EXE."
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="e05ecc14c86d96d64495434a7e34f35588538ae2e6da20c2dacc4a97001c35df",
                        features={"obfuscator": [FV(".NET Reactor 4.0")]},
                    )
                ],
            ),
        )

    def test_confuserex_obfus_dotnet(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "d30feab410f4b260f6ec56d39969ac8673a585fae4c1308d51136bcd8af0100d",
                        "Malicious Windows 32EXE, ConfuserEx obfuscation.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_EMPTY, message="De4dot does not know how to deobfuscate this file.")
            ),
        )

    def test_dotnet_smart_assembly(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "f5d82956ceca26f10317df7cfbfacfe99d3854b8aa3fea507e28676f6a6cd9ed",
                        "Malicious .NET Windows 32EXE, malware family REMCOS",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="f5d82956ceca26f10317df7cfbfacfe99d3854b8aa3fea507e28676f6a6cd9ed",
                        features={"obfuscator": [FV("SmartAssembly 6.9.0.114")]},
                    )
                ],
            ),
        )

    def test_obfus_dotnet_reactor_eziriz(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "45dc4518fbf43bf4611446159f72cdbc37641707bb924bd2a52644a3af5bab76",
                        "Malicious Windows 32EXE, keylogger malware family AgentTesla.",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        sha256="45dc4518fbf43bf4611446159f72cdbc37641707bb924bd2a52644a3af5bab76",
                        features={"obfuscator": [FV(".NET Reactor")]},
                    )
                ],
            ),
        )

    def test_obfus_dotnet_manually_obfuscated(self):
        result = self.do_execution(
            data_in=[
                (
                    "content",
                    self.load_test_file_bytes(
                        "083f741817703fc9a9d53267eb5b2d45f579cca7c922a014e2c5dbaf85f0611d",
                        "Malicious Windows 32EXE, malware family Njrat",
                    ),
                )
            ]
        )
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_EMPTY, message="De4dot does not know how to deobfuscate this file.")
            ),
        )

    def test_malformed_dotnet_file(self):
        """Test a run where the file is a mono dotnet file but has content has been modified."""
        data = self.load_test_file_bytes(
            "b13049711027802304b0f50291d5557e76113b46c0a2258b919e65d519ace2f2", "Malicious .NET Windows 32EXE."
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="b13049711027802304b0f50291d5557e76113b46c0a2258b919e65d519ace2f2",
                        features={"malformed": [FV("Malformed dotnet file (may be version > 3.1).")]},
                    )
                ],
            ),
        )

    def test_unknown_deob(self):
        """Test a run where the file has been obfuscated with an obfuscator de4dot doesn't recognise."""
        data = self.load_test_file_bytes(
            "6ade497b4a45a2c4688ac69fe2ae146c721db3cf8d82df9b5ca40b4614ad62b7",
            "Malicious .NET Windows 32EXE, malware family AgentTesla.",
        )
        result = self.do_execution(data_in=[("content", data)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED_EMPTY, message="De4dot does not know how to deobfuscate this file.")
            ),
        )
