import struct

class MSSQL_VERSION:
    # Build by @splouchy from https://sqlserverbuilds.blogspot.com/
    # Added by @Deft_
    VERSION_NAME = ("Microsoft SQL Server", {
        6 : ("6", {
            0 : (".0", {
                121 : "RTM (no SP)",
                124 : "(SP1)",
                139 : "(SP2)",
                151 : "(SP3)",
            }),
            50 : (".5", {
                201 : "RTM (no SP)",
                213 : "(SP1)",
                240 : "(SP2)",
                258 : "(SP3)",
                281 : "(SP4)",
                416 : "(SP5)",
            }),
        }),
        7 : ("7", {
            0 : ("", {
                623 : "RTM (no SP)",
                699 : "(SP1)",
                842 : "(SP2)",
                961 : "(SP3)",
                1063 : "(SP4)",
            }),
        }),
        8 : ("2000", {
            0 : ("", {
                194 : "RTM (no SP)",
                384 : "(SP1)",
                532 : "(SP2)",
                760 : "(SP3)",
                2039 : "(SP4)",
            }),
        }),
        9 : ("2005", {
            0 : ("", {
                1399 : "RTM (no SP)",
                2047 : "(SP1)",
                3042 : "(SP2)",
                4035 : "(SP3)",
                5000 : "(SP4)",
            }),
        }),
        10 : ("2008", {
            0 : ("", {
                1600 : "RTM (no SP)",
                2531 : "(SP1)",
                4000 : "(SP2)",
                5500 : "(SP3)",
                6000 : "(SP4)",
            }),
            50 : (" R2", {
                1600 : "RTM (no SP)",
                2500 : "(SP1)",
                4000 : "(SP2)",
                6000 : "(SP3)",
            }),
        }),
        11 : ("2012", {
            0 : ("", {
                2100 : "RTM (no SP)",
                3000 : "(SP1)",
                5058 : "(SP2)",
                6020 : "(SP3)",
                7001 : "(SP4)",
            }),
        }),
        # Supported
        12 : ("2014", {
            0 : ("", {
                2000 : "RTM (no SP)",
                4100 : "(SP1)",
                5000 : "(SP2)",
                6024 : "(SP3)",
            }),
        }),
        13 : ("2016", {
            0 : ("", {
                1601 : "RTM (no SP)",
                4001 : "(SP1)",
                5026 : "(SP2)",
                6300 : "(SP3)",
            }),
        }),
        14 : ("2017", {
            0 : ("", {
                1000 : "RTM",
                3006 : "(CU1)",
                3008 : "(CU2)",
                3015 : "(CU3)",
                3022 : "(CU4)",
                3023 : "(CU5)",
                3025 : "(CU6)",
                3026 : "(CU7)",
                3029 : "(CU8)",
                3030 : "(CU9)",
                3037 : "(CU10)",
                3038 : "(CU11)",
                3045 : "(CU12)",
                3048 : "(CU13)",
                3076 : "(CU14)",
                3162 : "(CU15)",
                3223 : "(CU16)",
                3228 : "(CU17)",
                3257 : "(CU18)",
                3281 : "(CU19)",
                3294 : "(CU20)",
                3335 : "(CU21)",
                3356 : "(CU22)",
                3381 : "(CU23)",
                3391 : "(CU24)",
                3401 : "(CU25)",
                3411 : "(CU26)",
                3421 : "(CU27)",
                3430 : "(CU28)",
                3436 : "(CU29)",
                3451 : "(CU30)",
                3456 : "(CU31)",
            }),
        }),
        15 : ("2019", {
            0 : ("", {
                2000 : "RTM",
                4003 : "(CU1)",
                4013 : "(CU2)",
                4023 : "(CU3)",
                4033 : "(CU4)",
                4043 : "(CU5)",
                4053 : "(CU6)",
                4063 : "(CU7)",
                4073 : "(CU8)",
                4102 : "(CU9)",
                4123 : "(CU10)",
                4138 : "(CU11)",
                4153 : "(CU12)",
                4178 : "(CU13)",
                4188 : "(CU14)",
                4198 : "(CU15)",
                4223 : "(CU16)",
                4249 : "(CU17)",
                4261 : "(CU18)",
                4298 : "(CU19)",
                4312 : "(CU20)",
            }),
        }),
        16 : ("2022", {
            0 : ("", {
                1000 : "RTM",
                4003 : "(CU1)",
                4015 : "(CU2)",
                4025 : "(CU3)",
                4035 : "(CU4)",
            }),
        }),
    })

    def __init__(self, version):
        self.major, self.minor, self.build = struct.unpack_from(">bbH", version)

    @property
    def version_number(self):
        return f"{self.major}.{self.minor}.{self.build}"

    @property
    def version_name(self):
        try:
            string = MSSQL_VERSION.VERSION_NAME[0]
            string += " "
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][0]
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][1][self.minor][0]
            string += " "
            string += MSSQL_VERSION.VERSION_NAME[1][self.major][1][self.minor][1][self.build]
        except KeyError:
            pass
        finally:
            return string

    def __repr__(self):
        return f"{self.version_name} ({self.version_number})"
