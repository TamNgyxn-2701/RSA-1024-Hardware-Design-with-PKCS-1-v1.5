# ============================================================
#  RSA2 DECRYPT SIMULATION
#  Flow: ciphertext + d/N -> RTL decrypt -> message
# ============================================================

puts ""
puts "============================================================"
puts " RSA2 DECRYPT SIMULATION"
puts " Flow: ciphertext + d/N -> RTL decrypt -> message"
puts "============================================================"
puts ""

# Neu may ban dung py thay vi python thi sua dong nay thanh:
# set PYTHON_CMD py
set PYTHON_CMD python

# Chon ciphertext
puts "Chon ciphertext C:"
puts "  1. Nhap C thu cong"
puts "  2. Dung C co san tu tb/rsa1024_vectors.vh"
puts "  3. Thoat"
puts -nonewline {Chon [1/2/3]: }
flush stdout
gets stdin c_choice

if {$c_choice == "3"} {
    puts "Thoat run_decrypt.do."
    return
}

if {$c_choice == "1"} {
    puts ""
    puts "Nhap ciphertext C dang hex:"
    puts -nonewline {C_HEX: }
    flush stdout
    gets stdin c_value

} elseif {$c_choice == "2"} {
    set c_value "VECTOR"

} else {
    puts "Lua chon khong hop le. Thoat run_decrypt.do."
    return
}

puts ""
puts "Chon khoa decrypt:"
puts "  1. Nhap N va d"
puts "  2. Dung N/d co san"
puts "     - Uu tien N/d vua luu tu lan encrypt gan nhat"
puts "     - Neu khong co thi dung N/d mac dinh trong vector"
puts "  3. Thoat"
puts -nonewline {Chon [1/2/3]: }
flush stdout
gets stdin key_choice

if {$key_choice == "3"} {
    puts "Thoat run_decrypt.do."
    return
}

if {$key_choice == "1"} {
    puts ""
    puts "Nhap N va d dang hex."

    puts -nonewline {N_HEX: }
    flush stdout
    gets stdin n_value

    puts -nonewline {D_HEX: }
    flush stdout
    gets stdin d_value

    puts -nonewline {Nhap MESSAGE_BYTES [Enter = 14]: }
    flush stdout
    gets stdin msg_bytes

    if {$msg_bytes == ""} {
        set msg_bytes 14
    }

    puts ""
    puts "Dang tao tham so decrypt tu N/d custom..."

    exec $PYTHON_CMD scripts/rsa2_gen_params.py decrypt --mode custom --c $c_value --n $n_value --d $d_value --msg-bytes $msg_bytes

} elseif {$key_choice == "2"} {
    puts -nonewline {Nhap MESSAGE_BYTES [Enter = tu lan encrypt gan nhat hoac 14]: }
    flush stdout
    gets stdin msg_bytes

    if {$msg_bytes == ""} {
        set msg_bytes "AUTO"
    }

    puts ""
    puts "Dang tao tham so decrypt tu N/d co san..."

    exec $PYTHON_CMD scripts/rsa2_gen_params.py decrypt --mode vector --c $c_value --msg-bytes $msg_bytes

} else {
    puts "Lua chon khong hop le. Thoat run_decrypt.do."
    return
}

puts ""
puts "============================================================"
puts " Compile RTL Decrypt"
puts "============================================================"

if {[file exists work]} {
    vdel -lib work -all
}
vlib work

vlog -work work +incdir+tb rtl/montgomery_multiplier.v
vlog -work work +incdir+tb rtl/rsa_modexp_mont.v
vlog -work work +incdir+tb rtl/rsa1024_top.v
vlog -work work +incdir+tb rtl/pkcs1_v15_checker.v
vlog -work work +incdir+tb rtl/rsa1024_pkcs1_decrypt_top.v
vlog -work work +incdir+tb tb/tb_fixed_decrypt.v

puts ""
puts "============================================================"
puts " Run Decrypt Simulation"
puts "============================================================"

vsim work.tb_fixed_decrypt
run -all

puts ""
puts "============================================================"
puts " Decrypt simulation finished."
puts " Xem PKCS1_VALID va PLAINTEXT_ASCII o ket qua phia tren."
puts "============================================================"