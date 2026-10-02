import base64
import zlib
import re


# ============================================================
# RXPGuides crypto implementation
# Based on rxp-crypto.ts
# ============================================================


def derive_key(battletag: str) -> bytes:
    """Derive the 16-byte RC4 key from a BattleTag."""

    data = battletag.lower().encode("utf-8")

    if len(data) > 16:
        data = data[-16:]

    buffer = bytearray(16)

    k = 16 - len(data)

    for i in range(16):
        j = (i - k) & 0xF

        if j < len(data):
            buffer[i] = data[j]

    for i in range(16):
        buffer[(-i) & 0xF] = (
            buffer[(15 - i) & 0xF]
            ^ buffer[(13 - i) & 0xF]
            ^ buffer[(12 - i) & 0xF]
            ^ buffer[(10 - i) & 0xF]
        )

    return bytes(buffer)


def rc4_ksa(key: bytes) -> list:
    """RC4 Key Scheduling Algorithm."""

    S = list(range(256))
    j = 0

    for i in range(256):
        j = (j + S[i] + key[i & 0xF]) & 0xFF

        S[i], S[j] = S[j], S[i]

    return S


def rc4_crypt(s_box: list, data: bytes) -> bytes:
    """RC4 encryption/decryption."""

    S = s_box.copy()

    i = 0
    j = 0

    output = bytearray(len(data))

    for k in range(len(data)):
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF

        S[i], S[j] = S[j], S[i]

        output[k] = data[k] ^ S[(S[i] + S[j]) & 0xFF]

    return bytes(output)


def adler32(data: bytes) -> int:
    """Adler-32 checksum matching the TypeScript implementation."""

    a = 1
    b = 0

    for byte in data:
        a = (a + byte) % 65521
        b = (b + a) % 65521

    return ((b * 65536 + a) & 0xFFFFFFFF)


# ============================================================
# Decrypt
# ============================================================

def decrypt_guide_file(raw: str, battletag: str):
    """
    Decrypt an RXPGuides export.

    Returns:
        plaintext
        version
        guide_count
    """

    # Version is stored at the end of the file.
    version_match = re.search(r"\|(\d+)$", raw)

    if version_match:
        version = int(version_match.group(1))
    else:
        version = 40000

    key = derive_key(battletag)
    S = rc4_ksa(key)

    chunks = re.findall(
        r"(-?\d+)(\D)([A-Za-z0-9+/=]+)%",
        raw
    )

    all_guides = []

    for _, mode, content in chunks:

        # ':' means encrypted guide data
        if mode == ":":

            try:
                decoded = base64.b64decode(content)

                decrypted = rc4_crypt(
                    S,
                    decoded
                )

                # pako.inflate() uses the zlib/DEFLATE format.
                decompressed = zlib.decompress(
                    decrypted
                )

                text = decompressed.decode(
                    "utf-8",
                    errors="replace"
                )

                guides = [
                    guide
                    for guide in text.split("\x00")
                    if guide.strip()
                ]

                all_guides.extend(guides)

            except Exception as e:
                raise ValueError(
                    "Could not decrypt the file. "
                    "The original BattleTag may be incorrect."
                ) from e

    if not all_guides:
        raise ValueError(
            "No guides could be decrypted. "
            "Check the original BattleTag."
        )

    plaintext = "\x00".join(all_guides)

    return plaintext, version, len(all_guides)


# ============================================================
# Encrypt
# ============================================================

def encrypt_for_battletag(
    plaintext: str,
    battletag: str,
    version: int
) -> str:

    data = plaintext.encode("utf-8")

    # Same calculation as:
    # new TextDecoder().decode(data).split("\x00").length
    n_guides = len(
        plaintext.split("\x00")
    )

    checksum = adler32(data)

    # Equivalent to pako.deflate(data)
    compressed = zlib.compress(data)

    key = derive_key(battletag)

    S = rc4_ksa(key)

    encrypted = rc4_crypt(
        S,
        compressed
    )

    encoded = base64.b64encode(
        encrypted
    ).decode("ascii")

    return (
        f"{n_guides}|"
        f"{checksum}:"
        f"{encoded}%|"
        f"{version}"
    )


# ============================================================
# Main
# ============================================================

def main():

    print()
    print("======================================")
    print("       RXPGuides Re-encryptor")
    print("======================================")
    print()

    # --------------------------------------------------------
    # Read input
    # --------------------------------------------------------

    try:
        with open(
            "input.txt",
            "r",
            encoding="utf-8"
        ) as f:
            raw = f.read()

    except FileNotFoundError:
        print("ERROR: input.txt was not found.")
        input("Press Enter to exit...")
        return

    # --------------------------------------------------------
    # Detect version
    # --------------------------------------------------------

    version_match = re.search(
        r"\|(\d+)$",
        raw
    )

    if version_match:
        version = int(version_match.group(1))
    else:
        version = 40000

    print(f"Detected version: {version}")
    print()

    # --------------------------------------------------------
    # Original BattleTag
    # --------------------------------------------------------

    original_battletag = input(
        "Original BattleTag: "
    ).strip()

    if not original_battletag:
        print("ERROR: Original BattleTag cannot be empty.")
        input("Press Enter to exit...")
        return

    print()
    print(f"Original BattleTag: {original_battletag}")
    print(f"Original version:   {version}")
    print()

    # --------------------------------------------------------
    # New BattleTag
    # --------------------------------------------------------

    new_battletag = input(
        "New BattleTag: "
    ).strip()

    if not new_battletag:
        print("ERROR: New BattleTag cannot be empty.")
        input("Press Enter to exit...")
        return

    print()
    print("--------------------------------------")
    print(f"From:    {original_battletag}")
    print(f"To:      {new_battletag}")
    print(f"Version: {version}")
    print("--------------------------------------")
    print()

    # --------------------------------------------------------
    # Decrypt
    # --------------------------------------------------------

    print("Decrypting input.txt...")

    try:
        plaintext, detected_version, guide_count = (
            decrypt_guide_file(
                raw,
                original_battletag
            )
        )

    except Exception as e:
        print()
        print("ERROR: Could not decrypt input.txt.")
        print()
        print(str(e))
        print()
        input("Press Enter to exit...")
        return

    print(
        f"Successfully decrypted "
        f"{guide_count} guide(s)."
    )

    # --------------------------------------------------------
    # Re-encrypt
    # --------------------------------------------------------

    print(
        f"Encrypting for {new_battletag}..."
    )

    output = encrypt_for_battletag(
        plaintext,
        new_battletag,
        detected_version
    )

    # --------------------------------------------------------
    # Write output
    # --------------------------------------------------------

    with open(
        "output.txt",
        "w",
        encoding="utf-8"
    ) as f:
        f.write(output)

    print()
    print("======================================")
    print("             COMPLETE")
    print("======================================")
    print()
    print(f"Original BattleTag: {original_battletag}")
    print(f"New BattleTag:      {new_battletag}")
    print(f"Version:            {detected_version}")
    print(f"Guides:             {guide_count}")
    print()
    print("Created: output.txt")
    print()

    input("Press Enter to exit...")


if __name__ == "__main__":
    main()
