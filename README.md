# Vietcong CBF Unpacker v1.0.0

Python unpacker for CBF archives from the game **Vietcong** (2003, Pterodon/Illusion Softworks).

Correctly handles **multi-chunk LZW compression** — a known issue in other CBF extraction tools (`cbfext`, Dragon UnPACKer) where only the first LZW chunk is decompressed, producing truncated files.

## What it does

- Extracts all files from `.CBF` archives with full multi-chunk LZW decompression
- Decrypts encrypted file tables (ZBL1 retail archives)
- Decrypts uncompressed file data
- Pure Python — no compiled dependencies

## The multi-chunk problem

Larger files in CBF archives are split into multiple consecutive LZW chunks. Each chunk has a 12-byte header (`[..]` magic + sizes). Most existing tools read only the first chunk, resulting in truncated DDS textures, broken BES models, and incomplete BMP images. This unpacker reads all chunks.

## Requirements

- Python 3.6 or newer
- No additional dependencies (pure Python, standard library only)

## Usage

All commands below are for **Windows PowerShell** (or Command Prompt). On Linux/macOS, the syntax is the same.

### Extract entire CBF archive

```bash
python cbf_unpacker.py <file.cbf> <output_dir>
```

### Extract only specific file types

```bash
python cbf_unpacker.py <file.cbf> <output_dir> --filter .dds
python cbf_unpacker.py <file.cbf> <output_dir> --filter .bes
```

### List contents without extracting

```bash
python cbf_unpacker.py <file.cbf> --list
```

### Example: Extract the full game

Assuming Vietcong is installed in `<VCDIR>` and you want to extract to `<VCDIR>/.unpacked`.

CBF filenames contain a language code (`cz` = Czech, `en` = English, `de` = German, etc.). Replace `cz` with your language version in the commands below.

```bash
cd <VCDIR>

# Main game (replace "cz" with your language code, e.g. "en", "de", "fr")
python cbf_unpacker.py vietcong_cz_01.cbf .unpacked/VC
python cbf_unpacker.py vietcong_cz_02.cbf .unpacked/VC
python cbf_unpacker.py vietcong_cz_dub.cbf .unpacked/VC
python cbf_unpacker.py vietcong_cz_gsp.cbf .unpacked/VC
python cbf_unpacker.py vietcong_cz_xtl.cbf .unpacked/VC

# Patches
python cbf_unpacker.py vietcong_101.cbf .unpacked/VC/Patches/101
python cbf_unpacker.py vietcong_120.cbf .unpacked/VC/Patches/120
python cbf_unpacker.py vietcong_130.cbf .unpacked/VC/Patches/130
python cbf_unpacker.py vietcong_140.cbf .unpacked/VC/Patches/140
python cbf_unpacker.py vietcong_150.cbf .unpacked/VC/Patches/150
python cbf_unpacker.py vietcong_160.cbf .unpacked/VC/Patches/160

# DLC — Fist Alpha (replace "cze" with your language code)
python cbf_unpacker.py addons/fistalpha/fistalpha_01.cbf .unpacked/FA
python cbf_unpacker.py addons/fistalpha/fistalpha_02.cbf .unpacked/FA
python cbf_unpacker.py addons/fistalpha/fistalpha_03.cbf .unpacked/FA
python cbf_unpacker.py addons/fistalpha/fistalpha_cze_dub.cbf .unpacked/FA
python cbf_unpacker.py addons/fistalpha/fistalpha_cze_gen.cbf .unpacked/FA
python cbf_unpacker.py addons/fistalpha/fistalpha_cze_snd.cbf .unpacked/FA
python cbf_unpacker.py addons/fistalpha/fistalpha_cze_xtl.cbf .unpacked/FA

# DLC — Red Dawn
python cbf_unpacker.py addons/reddawn/reddawn.cbf .unpacked/RD
```

### Use as a library

```python
from cbf_unpacker import parse_cbf, extract_file, LZW_MAGIC

entries = parse_cbf('vietcong_cz_01.cbf')
with open('vietcong_cz_01.cbf', 'rb') as f:
    for entry in entries:
        data, chunks = extract_file(f, entry['offset'], entry['size'])
        # write data to disk
```

## Tested on

| Archive | Files | Size | Errors |
|---------|-------|------|--------|
| vietcong_cz_01.cbf | 17,192 | 1,204.8 MB | 0 |
| vietcong_cz_02.cbf | 6,984 | 674.6 MB | 0 |
| vietcong_cz_dub.cbf | 3,061 | 104.2 MB | 0 |
| vietcong_cz_gsp.cbf | 3,771 | 46.2 MB | 0 |
| vietcong_cz_xtl.cbf | 7,019 | 2.0 MB | 0 |
| setup.cbf | 67 | 1.4 MB | 0 |
| Patches (101–160) | 4,173 | 173.3 MB | 0 |
| Fist Alpha (all) | 13,637 | 1,251.8 MB | 0 |
| Red Dawn | 5,036 | 550.3 MB | 0 |
| **Total** | **60,940** | **4,008.6 MB** | **0** |

## Credits

- **Luigi Auriemma** — `cbfext.c` and `unlzw.c` (GPLv2) — table decryption and LZW algorithm
- **Romop5** — [vietcong-unpacker](https://github.com/Romop5/vietcong-unpacker) — CBF format documentation
- **OpenVietcong** — [vc-spec](https://github.com/OpenVietcong/vc-spec) — file format specifications

## License

GPLv2 (derived from cbfext.c and unlzw.c by Luigi Auriemma)
