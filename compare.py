#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from __future__ import annotations

from pathlib import Path
import math
import re

K_BITS = 1024
K_BYTES = 128
HEX_W = K_BITS // 4
MAX_MSG_BYTES = K_BYTES - 11
DEFAULT_E = 65537

ROOT = Path(__file__).resolve().parent
TB_DIR = ROOT / "tb"
OUT_DIR = ROOT / "cli_outputs"
VEC_FILE = TB_DIR / "rsa1024_vectors.vh"

# Fallback neu khong tim thay tb/rsa1024_vectors.vh
FALLBACK_N_HEX = (
    "8cb7930fa753367c23f8dbef367e9337a916bda66b8905779727f1685908cc75e4ea28a0ec30fa3fc93721f0cedda0143a9a9c207b643381ac0531da51769ecbca5fbf1b23dbdaf423488f28b760a04ef5fbe6542605f7f7f5c50afc23f5e32d7ad014120a0102725ecf5dab079b2224deec6cdd9a0e39df468ec554a4bad775"
)

FALLBACK_E_HEX = "10001"

FALLBACK_D_HEX = (
    "6852b4d17720a71533ea0ccbf51fb3ef2109be028258ec57b415a5d0d1a94743e43981738487ef0f9912a9b408f99ff33f5b5e826a5868232bb0123ca4068844bb86a50bd4d99565130e0669166dbd0bfc8342bc83c5b215fd0778dabb5342e3fcf037ebffd60f3312da5672d2c3bb8fc3d42a08cb28c8a343e3e38cf5747245"
)


def hr(char: str = "=") -> None:
    print(char * 72)


def title(text: str) -> None:
    print()
    hr("=")
    print(f" {text}")
    hr("=")


def section(text: str) -> None:
    print()
    print(f"--- {text} ---")


def menu_item(num: int, text: str) -> None:
    print(f"  {num}. {text}")


def prompt_choice(valid: set[str]) -> str:
    choice = input("Chon: ").strip()
    while choice not in valid:
        print("Lua chon khong hop le. Hay nhap lai.")
        choice = input("Chon: ").strip()
    return choice


def kv(name: str, value: object = "") -> None:
    print(f"{name:<18}: {value}")


def kv_blank() -> None:
    print()


def kv_hex(name: str, value: int | str, fixed_1024: bool = False) -> None:
    if isinstance(value, int):
        hex_text = int_hex_1024(value) if fixed_1024 else hex_compact(value)
    else:
        hex_text = clean_hex(value)

    print(f"{name:<18}: {hex_text}")
    print()


def clean_hex(text: str) -> str:
    text = text.strip().lower().replace("_", "").replace(" ", "")
    if text.startswith("0x"):
        text = text[2:]
    return "".join(ch for ch in text if ch in "0123456789abcdef")


def parse_int_auto(text: str) -> int:
    """Nhap duoc decimal hoac hex. Hex co the co 0x hoac co chu a-f."""
    raw = text.strip().replace("_", "").replace(" ", "")
    if not raw:
        raise ValueError("Khong duoc de trong.")

    low = raw.lower()

    if low.startswith("0x"):
        return int(clean_hex(low), 16)

    if any(ch in "abcdefABCDEF" for ch in raw):
        return int(clean_hex(raw), 16)

    return int(raw, 10)


def read_int_auto(prompt: str) -> int:
    return parse_int_auto(input(prompt).strip())


def read_hex_int(prompt: str, default: int | None = None) -> int:
    if default is None:
        raw = input(prompt).strip()
    else:
        raw = input(f"{prompt} [Enter = mac dinh]: ").strip()
        if not raw:
            return default

    hx = clean_hex(raw)

    if not hx:
        raise ValueError("Chuoi hex rong.")

    return int(hx, 16)


def int_hex_1024(x: int) -> str:
    if x < 0:
        raise ValueError("Gia tri khong duoc am.")

    if x >= (1 << K_BITS):
        raise ValueError("Gia tri lon hon 1024 bit, khong phu hop voi project RSA-1024.")

    return f"{x:0{HEX_W}x}"


def hex_compact(x: int) -> str:
    return f"{x:x}"


def bit_info(name: str, value: int) -> str:
    return f"{name}: {value.bit_length()} bit"


def parse_vectors() -> dict[str, int]:
    values: dict[str, int] = {}

    if VEC_FILE.exists():
        text = VEC_FILE.read_text(encoding="utf-8", errors="ignore")

        for name in ["RSA_N", "RSA_E", "RSA_D", "RSA_R", "RSA_R2", "RSA_C", "RSA_M"]:
            m = re.search(rf"`define\s+{name}\s+1024'h([0-9a-fA-F]+)", text)
            if m:
                values[name] = int(m.group(1), 16)

    if "RSA_N" not in values:
        values["RSA_N"] = int(FALLBACK_N_HEX, 16)

    if "RSA_E" not in values:
        values["RSA_E"] = int(FALLBACK_E_HEX, 16)

    if "RSA_D" not in values:
        values["RSA_D"] = int(FALLBACK_D_HEX, 16)

    return values


def r_values(n: int) -> tuple[int, int]:
    if n <= 0:
        raise ValueError("N phai > 0")

    r = (1 << K_BITS) % n
    r2 = pow(1 << K_BITS, 2, n)

    return r, r2


def is_probable_prime(n: int) -> bool:
    """Miller-Rabin du dung cho demo/lab, khong dung cho bao mat that."""
    if n < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]

    for p in small_primes:
        if n == p:
            return True

        if n % p == 0:
            return False

    d = n - 1
    s = 0

    while d % 2 == 0:
        s += 1
        d //= 2

    for a in small_primes:
        if a >= n - 2:
            continue

        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)

            if x == n - 1:
                break
        else:
            return False

    return True


def compute_key_from_pq(p: int, q: int, e: int = DEFAULT_E) -> tuple[int, int, int]:
    if p == q:
        raise ValueError("p va q phai khac nhau.")

    if not is_probable_prime(p):
        raise ValueError("p khong phai so nguyen to theo kiem tra Miller-Rabin.")

    if not is_probable_prime(q):
        raise ValueError("q khong phai so nguyen to theo kiem tra Miller-Rabin.")

    n = p * q
    phi = (p - 1) * (q - 1)

    if math.gcd(e, phi) != 1:
        raise ValueError("e khong nguyen to cung nhau voi phi(N), hay chon p/q khac hoac e khac.")

    d = pow(e, -1, phi)

    return n, e, d


def save_last_key(n: int, e: int, d: int, msg_len: int | None = None, c: int | None = None) -> None:
    OUT_DIR.mkdir(exist_ok=True)

    (OUT_DIR / "last_key.txt").write_text(
        f"N={hex_compact(n)}\nE={hex_compact(e)}\nD={hex_compact(d)}\n",
        encoding="utf-8",
    )

    if msg_len is not None:
        (OUT_DIR / "last_message_len.txt").write_text(str(msg_len), encoding="utf-8")

    if c is not None:
        (OUT_DIR / "last_ciphertext.txt").write_text(hex_compact(c), encoding="utf-8")


def load_last_key() -> tuple[int, int, int] | None:
    f = OUT_DIR / "last_key.txt"

    if not f.exists():
        return None

    data: dict[str, int] = {}

    for line_text in f.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line_text:
            k, v = line_text.split("=", 1)
            data[k.strip().upper()] = int(clean_hex(v), 16)

    if all(k in data for k in ["N", "E", "D"]):
        return data["N"], data["E"], data["D"]

    return None


def load_last_message_len(default: int = 14) -> int:
    f = OUT_DIR / "last_message_len.txt"

    if not f.exists():
        return default

    try:
        return int(f.read_text(encoding="utf-8").strip())
    except Exception:
        return default


def print_key_summary(n: int, e: int, d: int, source: str) -> None:
    section("KEY SUMMARY")
    kv("Nguon khoa", source)
    kv("N bit-length", f"{n.bit_length()} bit")
    kv("e decimal", e)
    kv("e hex", hex_compact(e))
    kv("d bit-length", f"{d.bit_length()} bit")
    kv_blank()

    if n.bit_length() != K_BITS:
        print("[WARN] N khong dung 1024 bit.")
        print("       Mach van nhan bus 1024-bit, nhung khong con dung nghia RSA-1024.")


def pkcs1_v15_encode_demo(message: bytes) -> bytes:
    """EM = 00 || 02 || PS || 00 || M, PS deterministic de khop lab."""
    if len(message) > MAX_MSG_BYTES:
        raise ValueError(f"Message qua dai. RSA-1024 PKCS#1 v1.5 toi da {MAX_MSG_BYTES} byte.")

    ps_len = K_BYTES - len(message) - 3

    if ps_len < 8:
        raise ValueError("PS phai dai it nhat 8 byte.")

    ps = bytes(((i % 255) + 1) for i in range(ps_len))

    return b"\x00\x02" + ps + b"\x00" + message


def pkcs1_v15_decode_expected_len(em: bytes, msg_bytes: int) -> tuple[bool, bytes]:
    """Decode theo kieu checker phan cung: MESSAGE_BYTES phai dung."""
    if len(em) != K_BYTES or msg_bytes <= 0 or msg_bytes > MAX_MSG_BYTES:
        return False, b""

    sep_index = K_BYTES - msg_bytes - 1

    if sep_index < 10:
        return False, b""

    header_ok = em[0] == 0x00 and em[1] == 0x02
    sep_ok = em[sep_index] == 0x00
    ps = em[2:sep_index]
    ps_ok = len(ps) >= 8 and all(b != 0 for b in ps)

    return bool(header_ok and sep_ok and ps_ok), em[sep_index + 1:]


def choose_encrypt_key(vec: dict[str, int]) -> tuple[int, int, int] | None:
    title("CHON KHOA ENCRYPT")
    menu_item(1, "Nhap p, q")
    menu_item(2, "Dung du lieu co san tu tb/rsa1024_vectors.vh")
    menu_item(3, "Thoat")

    choice = prompt_choice({"1", "2", "3"})

    if choice == "3":
        print("Thoat encrypt.")
        return None

    if choice == "1":
        section("NHAP p, q")

        p = read_int_auto("Nhap p: ")
        q = read_int_auto("Nhap q: ")

        kv("p bit-length", f"{p.bit_length()} bit")
        kv("q bit-length", f"{q.bit_length()} bit")

        raw_e = input(f"Nhap e [Enter = {DEFAULT_E}]: ").strip()
        e = DEFAULT_E if not raw_e else parse_int_auto(raw_e)

        n, e, d = compute_key_from_pq(p, q, e)

        print_key_summary(n, e, d, "Nhap p, q")

        return n, e, d

    n = vec["RSA_N"]
    e = vec.get("RSA_E", DEFAULT_E)
    d = vec.get("RSA_D", 0)

    print_key_summary(n, e, d, "Vector mac dinh")

    return n, e, d


def choose_decrypt_key(vec: dict[str, int]) -> tuple[int, int] | None:
    title("CHON KHOA DECRYPT")
    menu_item(1, "Nhap N va d")
    menu_item(2, "Dung N/d co san")
    print("     - Uu tien N/d vua luu tu lan encrypt gan nhat")
    print("     - Neu khong co thi dung N/d mac dinh trong vector")
    menu_item(3, "Thoat")

    choice = prompt_choice({"1", "2", "3"})

    if choice == "3":
        print("Thoat decrypt.")
        return None

    if choice == "1":
        section("NHAP N, d")

        n = read_hex_int("N_HEX: ")
        d = read_hex_int("D_HEX: ")

        print_key_summary(n, 0, d, "Nhap N/d")

        return n, d

    last = load_last_key()

    if last is not None:
        n, e, d = last

        print_key_summary(n, e, d, "N/d co san tu lan encrypt gan nhat")

        return n, d

    n = vec["RSA_N"]
    d = vec["RSA_D"]
    e = vec.get("RSA_E", DEFAULT_E)

    print_key_summary(n, e, d, "N/d mac dinh trong vector")

    return n, d


def encrypt_flow() -> None:
    title("RSA2 ENCRYPT COMPARE")

    vec = parse_vectors()
    key = choose_encrypt_key(vec)

    if key is None:
        return

    n, e, d = key

    section("NHAP MESSAGE")

    message = input("Nhap message can encrypt: ").encode("utf-8")
    em = pkcs1_v15_encode_demo(message)
    m = int.from_bytes(em, "big")

    if m >= n:
        raise ValueError("EM >= N. Hay dung N dung RSA-1024 va du lon.")

    c = pow(m, e, n)
    r, r2 = r_values(n)

    save_last_key(n, e, d, len(message), c)

    title("PYTHON ENCRYPT RESULT")

    section("THONG TIN MESSAGE")
    kv("MESSAGE_BYTES", len(message))
    kv("PLAINTEXT_ASCII", message.decode("utf-8", errors="replace"))
    kv_hex("PLAINTEXT_HEX", message.hex())

    section("THONG TIN KHOA")
    kv("N_BIT_LENGTH", f"{n.bit_length()} bit")
    kv("E_HEX compact", hex_compact(e))
    kv("D_BIT_LENGTH", f"{d.bit_length()} bit")
    kv_hex("N_HEX", n, fixed_1024=True)
    kv_hex("D_HEX", d, fixed_1024=False)

    section("THONG TIN MONTGOMERY")
    kv_hex("R_HEX", r, fixed_1024=True)
    kv_hex("R2_HEX", r2, fixed_1024=True)

    section("KET QUA ENCRYPT")
    kv_hex("EM_HEX", em.hex())
    kv_hex("CIPHERTEXT_HEX", c, fixed_1024=True)
    kv("SAVED", "cli_outputs/last_key.txt, last_message_len.txt, last_ciphertext.txt")

    hr("=")


def decrypt_flow() -> None:
    title("RSA2 DECRYPT COMPARE")
    print("Flow: ciphertext + d/N -> Python decrypt -> message")

    vec = parse_vectors()

    title("NHAP CIPHERTEXT")
    menu_item(1, "Nhap C")
    menu_item(2, "Dung C co san tu tb/rsa1024_vectors.vh")
    menu_item(3, "Thoat")

    c_choice = prompt_choice({"1", "2", "3"})

    if c_choice == "3":
        print("Thoat decrypt.")
        return

    if c_choice == "1":
        c = read_hex_int("C_HEX: ")
    else:
        if "RSA_C" not in vec:
            raise ValueError("Vector khong co RSA_C. Hay nhap C thu cong.")
        c = vec["RSA_C"]

    key = choose_decrypt_key(vec)

    if key is None:
        return

    n, d = key

    default_len = load_last_message_len(14)
    raw = input(f"Nhap MESSAGE_BYTES [Enter = {default_len}]: ").strip()
    msg_bytes = int(raw) if raw else default_len

    m = pow(c, d, n)
    em = m.to_bytes(K_BYTES, "big")
    pkcs_valid, plaintext = pkcs1_v15_decode_expected_len(em, msg_bytes)
    r, r2 = r_values(n)

    title("PYTHON DECRYPT RESULT")

    section("TRANG THAI")
    kv("MESSAGE_BYTES", msg_bytes)
    kv("PKCS1_VALID", 1 if pkcs_valid else 0)
    kv("N_BIT_LENGTH", f"{n.bit_length()} bit")

    section("THONG TIN INPUT")
    kv_hex("C_HEX", c, fixed_1024=True)
    kv_hex("D_HEX", d, fixed_1024=False)
    kv_hex("N_HEX", n, fixed_1024=True)

    section("THONG TIN MONTGOMERY")
    kv_hex("R_HEX", r, fixed_1024=True)
    kv_hex("R2_HEX", r2, fixed_1024=True)

    section("KET QUA DECRYPT")
    kv_hex("EM_HEX", em.hex())
    kv_hex("PLAINTEXT_HEX", plaintext.hex())
    kv("PLAINTEXT_ASCII", plaintext.decode("utf-8", errors="replace"))

    if not pkcs_valid:
        print()
        print("WARNING: PKCS1_VALID=0. Co the sai C, sai d/N, hoac MESSAGE_BYTES khong dung.")

    hr("=")


def main() -> None:
    while True:
        title("RSA-1024")
        menu_item(1, "Encrypt")
        menu_item(2, "Decrypt")
        menu_item(3, "Thoat")

        choice = prompt_choice({"1", "2", "3"})

        try:
            if choice == "1":
                encrypt_flow()
            elif choice == "2":
                decrypt_flow()
            elif choice == "3":
                print("Thoat.")
                break
        except Exception as exc:
            print(f"\n[ERROR] {exc}")


if __name__ == "__main__":
    main()