#!/usr/bin/env python3
import re
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
FUZZ_PATCH = SCRIPT_DIR / "fuzz.patch.c"
ROOT = Path.cwd()


def replace_block_regex(target: Path, pattern: re.Pattern, replacement: str) -> None:
    text = target.read_text()
    new_text, count = pattern.subn(replacement, text, count=1)
    if count != 1:
        raise SystemExit(
            f"[!] Expected to patch exactly one block in {target}, but matched {count}."
        )
    target.write_text(new_text)


# Enable fuzzing via constructor hook
main_body = FUZZ_PATCH.read_text()
server_main = ROOT / "server" / "main.c"
if not server_main.exists():
    raise SystemExit(
        f"[!] Expected to find server/main.c under {ROOT}, but it was missing. "
        "Run this script from the extracted httpd source directory."
    )

marker = "/* AFL fuzzing helpers injected into httpd */"
helpers_block = re.compile(
    r"\nstatic void net_iface_up\(.*__attribute__\(\(constructor\)\)\s+static void "
    r"start_afl_fuzzing\(void\)\s*\{.*",
    re.DOTALL,
)
sentinel_starts = [
    "static void net_iface_up(",
    "static void *fuzzer_thread(",
    "static void launch_fuzzy_thread(",
    "__attribute__((constructor)) static void start_afl_fuzzing",
]


def strip_existing_helpers(text: str) -> tuple[str, bool]:
    if marker in text:
        return text.split(marker)[0], True

    match = helpers_block.search(text)
    if match:
        return helpers_block.split(text)[0], True

    positions = [text.find(s) for s in sentinel_starts if text.find(s) != -1]
    if positions:
        return text[: min(positions)], True

    return text, False


current_main, patched = strip_existing_helpers(server_main.read_text())
current_main = current_main.rstrip() + "\n\n" + main_body + "\n"
server_main.write_text(current_main)

if patched:
    print("[+] ./server/main.c already patched; refreshing AFL fuzz helpers\n")
else:
    print("[+] ./server/main.c is patched :^) \n")

# Disable randomness to improve stability
core_file = ROOT / "server" / "core.c"
needle = re.compile(r"rv\s*=\s*apr_generate_random_bytes\s*\(\s*seed\s*,\s*sizeof\s*\(\s*seed\s*\)\s*\)\s*;", re.MULTILINE)
disable_random = """
        // ---- PATCH -----
        // rv = apr_generate_random_bytes(seed, sizeof(seed));
        memcpy(seed, fuzz_constant_seed, sizeof(seed));
        rv = APR_SUCCESS;
        //-------------------------------------------------

"""
replace_block_regex(core_file, needle, disable_random)
print("[+] ./server/core.c is patched :^) \n")

seed_declaration = """
/* AFL: deterministic seed for fuzzing stability */
static const unsigned char fuzz_constant_seed[8] = {0x78, 0xAB, 0xF5, 0xDB, 0xE2, 0x7F, 0xD2, 0x8A};

"""

core_text = core_file.read_text()
if "fuzz_constant_seed" not in core_text:
    core_text = core_text.replace("#include \"httpd.h\"\n", "#include \"httpd.h\"\n\n" + seed_declaration, 1)
    core_file.write_text(core_text)
