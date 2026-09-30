#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rsa2_gen_params.py

Python chỉ dùng để tính tham số cho testbench cố định:
  - N, e, d
  - R = 2^1024 mod N
  - R2 = 2^2048 mod N
  - message / ciphertext / MESSAGE_BYTES

Python KHÔNG tự encrypt/decrypt RSA thay cho Verilog.
RSA encrypt/decrypt thật sự vẫn chạy bằng RTL trong ModelSim.
"""
from __future__ import annotations

import argparse
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TB_DIR = ROOT / "tb"
OUT_DIR = ROOT / "cli_outputs"
VEC_FILE = TB_DIR / "rsa1024_vectors.vh"

K_BITS = 1024
K_BYTES = 128
HEX_W = 256
MAX_MSG_BYTES = K_BYTES - 11
DEFAULT_E = 65537


def clean_hex(text: str) -> str:
    text = str(text).strip().lower().replace("_", "").replace(" ", "")
    if text.startswith("0x"):
        text = text[2:]
    return "".join(ch for ch in text if ch in "0123456789abcdef")


def parse_int_auto(text: str) -> int:
    raw = str(text).strip().replace("_", "").replace(" ", "")
    if not raw:
        raise ValueError("Giá trị rỗng")
    low = raw.lower()
    if low.startswith("0x"):
        return int(clean_hex(low), 16)
    if any(ch in "abcdefABCDEF" for ch in raw):
        return int(clean_hex(raw), 16)
    return int(raw, 10)


def int_hex_1024(x: int) -> str:
    if x < 0:
        raise ValueError("Giá trị âm không hợp lệ")
    if x >= (1 << K_BITS):
        raise ValueError("Giá trị lớn hơn 1024 bit, không phù hợp project RSA-1024")
    return f"{x:0{HEX_W}x}"


def bitlen(x: int) -> int:
    return int(x).bit_length()


def is_probable_prime(n: int) -> bool:
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

    # Đủ dùng cho demo/lab, không dùng cho sinh khóa bảo mật thật.
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    for a in bases:
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


def parse_vectors() -> dict[str, int]:
    if not VEC_FILE.exists():
        raise FileNotFoundError(f"Không tìm thấy {VEC_FILE}")
    text = VEC_FILE.read_text(encoding="utf-8", errors="ignore")
    values: dict[str, int] = {}
    for name in ["RSA_N", "RSA_E", "RSA_D", "RSA_R", "RSA_R2", "RSA_C", "RSA_M"]:
        m = re.search(rf"`define\s+{name}\s+1024'h([0-9a-fA-F]+)", text)
        if m:
            values[name] = int(m.group(1), 16)
    if "RSA_N" not in values:
        raise ValueError("Không đọc được RSA_N trong tb/rsa1024_vectors.vh")
    values.setdefault("RSA_E", DEFAULT_E)
    return values


def r_values(n: int) -> tuple[int, int]:
    if n <= 0:
        raise ValueError("N phải > 0")
    r = (1 << K_BITS) % n
    r2 = pow(1 << K_BITS, 2, n)
    return r, r2


def compute_key_from_pq(p: int, q: int, e: int = DEFAULT_E) -> tuple[int, int, int]:
    if p == q:
        raise ValueError("p và q phải khác nhau")
    if not is_probable_prime(p):
        raise ValueError("p không phải số nguyên tố theo kiểm tra Miller-Rabin")
    if not is_probable_prime(q):
        raise ValueError("q không phải số nguyên tố theo kiểm tra Miller-Rabin")
    n = p * q
    phi = (p - 1) * (q - 1)
    if math.gcd(e, phi) != 1:
        raise ValueError("e không nguyên tố cùng nhau với phi(N). Hãy chọn p/q/e khác")
    d = pow(e, -1, phi)
    return n, e, d


def save_last_key(n: int, e: int, d: int, msg_len: int | None = None) -> None:
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "last_key.txt").write_text(
        f"N={n:x}\nE={e:x}\nD={d:x}\n", encoding="utf-8"
    )
    if msg_len is not None:
        (OUT_DIR / "last_message_len.txt").write_text(str(msg_len), encoding="utf-8")


def load_last_key() -> tuple[int, int, int] | None:
    f = OUT_DIR / "last_key.txt"
    if not f.exists():
        return None
    data: dict[str, int] = {}
    for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip().upper()] = int(clean_hex(v), 16)
    if all(k in data for k in ["N", "E", "D"]):
        return data["N"], data["E"], data["D"]
    return None


def last_msg_len(default: int = 14) -> int:
    f = OUT_DIR / "last_message_len.txt"
    if f.exists():
        try:
            return int(f.read_text().strip())
        except Exception:
            pass
    return default


def write_encrypt_params(message: bytes, n: int, e: int, d: int) -> None:
    if not message:
        raise ValueError("Message không được rỗng")
    if len(message) > MAX_MSG_BYTES:
        raise ValueError(f"Message quá dài. RSA-1024 PKCS#1 v1.5 tối đa {MAX_MSG_BYTES} byte")
    if n >= (1 << K_BITS):
        raise ValueError("N lớn hơn 1024 bit")
    r, r2 = r_values(n)
    bits = len(message) * 8

    TB_DIR.mkdir(exist_ok=True)
    content = f"""// Auto-generated by scripts/rsa2_gen_params.py
// Do not edit by hand unless you know what you are doing.

`define CLI_MESSAGE_BYTES {len(message)}
`define CLI_MSG_VALUE {bits}'h{message.hex()}
`define CLI_N_VALUE 1024'h{int_hex_1024(n)}
`define CLI_E_VALUE 1024'h{int_hex_1024(e)}
`define CLI_D_VALUE 1024'h{int_hex_1024(d)}
`define CLI_R_VALUE 1024'h{int_hex_1024(r)}
`define CLI_R2_VALUE 1024'h{int_hex_1024(r2)}
"""
    (TB_DIR / "cli_encrypt_params.vh").write_text(content, encoding="utf-8")
    save_last_key(n, e, d, len(message))

    print("\n================ PARAMS FOR ENCRYPT ================")
    print(f"MESSAGE_BYTES={len(message)}")
    print(f"PLAINTEXT_ASCII={message.decode('utf-8', errors='replace')}")
    print(f"PLAINTEXT_HEX={message.hex()}")
    print(f"N_BIT_LENGTH={bitlen(n)}")
    print(f"E_HEX={e:x}")
    print(f"D_HEX={int_hex_1024(d)}")
    print(f"N_HEX={int_hex_1024(n)}")
    print(f"R_HEX={int_hex_1024(r)}")
    print(f"R2_HEX={int_hex_1024(r2)}")
    if bitlen(n) != K_BITS:
        print("[WARN] N không đúng 1024 bit. Mạch vẫn nhận bus 1024-bit, nhưng không còn đúng nghĩa RSA-1024.")
    print("WROTE=tb/cli_encrypt_params.vh")
    print("====================================================")


def write_decrypt_params(cipher: int, n: int, d: int, msg_bytes: int) -> None:
    if msg_bytes <= 0 or msg_bytes > MAX_MSG_BYTES:
        raise ValueError(f"MESSAGE_BYTES phải nằm trong 1..{MAX_MSG_BYTES}")
    if cipher >= (1 << K_BITS):
        raise ValueError("Ciphertext lớn hơn 1024 bit")
    if n >= (1 << K_BITS):
        raise ValueError("N lớn hơn 1024 bit")
    r, r2 = r_values(n)

    TB_DIR.mkdir(exist_ok=True)
    content = f"""// Auto-generated by scripts/rsa2_gen_params.py
// Do not edit by hand unless you know what you are doing.

`define CLI_MESSAGE_BYTES {msg_bytes}
`define CLI_C_VALUE 1024'h{int_hex_1024(cipher)}
`define CLI_N_VALUE 1024'h{int_hex_1024(n)}
`define CLI_D_VALUE 1024'h{int_hex_1024(d)}
`define CLI_R_VALUE 1024'h{int_hex_1024(r)}
`define CLI_R2_VALUE 1024'h{int_hex_1024(r2)}
"""
    (TB_DIR / "cli_decrypt_params.vh").write_text(content, encoding="utf-8")

    print("\n================ PARAMS FOR DECRYPT ================")
    print(f"MESSAGE_BYTES={msg_bytes}")
    print(f"N_BIT_LENGTH={bitlen(n)}")
    print(f"C_HEX={int_hex_1024(cipher)}")
    print(f"D_HEX={int_hex_1024(d)}")
    print(f"N_HEX={int_hex_1024(n)}")
    print(f"R_HEX={int_hex_1024(r)}")
    print(f"R2_HEX={int_hex_1024(r2)}")
    print("WROTE=tb/cli_decrypt_params.vh")
    print("====================================================")


def cmd_encrypt(args: argparse.Namespace) -> None:
    vec = parse_vectors()
    if args.mode == "vector":
        n = vec["RSA_N"]
        e = vec.get("RSA_E", DEFAULT_E)
        d = vec.get("RSA_D", 0)
    elif args.mode == "pq":
        p = parse_int_auto(args.p)
        q = parse_int_auto(args.q)
        e = parse_int_auto(args.e) if args.e else DEFAULT_E
        n, e, d = compute_key_from_pq(p, q, e)
    else:
        raise ValueError("mode encrypt không hợp lệ")
    write_encrypt_params(args.message.encode("utf-8"), n, e, d)


def cmd_decrypt(args: argparse.Namespace) -> None:
    vec = parse_vectors()
    if args.mode == "vector":
        if "RSA_C" not in vec:
            raise ValueError("Vector không có RSA_C")
        c = vec["RSA_C"]
        n = vec["RSA_N"]
        d = vec["RSA_D"]
        msg_bytes = int(args.msg_bytes) if args.msg_bytes else last_msg_len()
    elif args.mode == "custom":
        c = parse_int_auto(args.c)
        d = parse_int_auto(args.d)
        # N có thể nhập, nếu bỏ trống thì ưu tiên N của lần encrypt gần nhất, nếu không có thì dùng vector.
        if args.n:
            n = parse_int_auto(args.n)
        else:
            last = load_last_key()
            n = last[0] if last is not None else vec["RSA_N"]
        msg_bytes = int(args.msg_bytes) if args.msg_bytes else last_msg_len()
    else:
        raise ValueError("mode decrypt không hợp lệ")
    write_decrypt_params(c, n, d, msg_bytes)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate fixed testbench params for RSA2 ModelSim simulation")
    sub = parser.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Generate tb/cli_encrypt_params.vh")
    enc.add_argument("--mode", choices=["vector", "pq"], required=True)
    enc.add_argument("--message", required=True)
    enc.add_argument("--p")
    enc.add_argument("--q")
    enc.add_argument("--e", default="")

    dec = sub.add_parser("decrypt", help="Generate tb/cli_decrypt_params.vh")
    dec.add_argument("--mode", choices=["vector", "custom"], required=True)
    dec.add_argument("--c", default="")
    dec.add_argument("--n", default="")
    dec.add_argument("--d", default="")
    dec.add_argument("--msg-bytes", default="")

    args = parser.parse_args()
    if args.cmd == "encrypt":
        cmd_encrypt(args)
    elif args.cmd == "decrypt":
        cmd_decrypt(args)


if __name__ == "__main__":
    main()
