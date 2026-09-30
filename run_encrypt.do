# ============================================================
#  RSA2 ENCRYPT SIMULATION
#  Flow: p/q or vector + message -> RTL encrypt -> ciphertext
# ============================================================

puts ""
puts "============================================================"
puts " RSA2 ENCRYPT SIMULATION"
puts " Flow: p/q or vector + message -> RTL encrypt -> ciphertext"
puts "============================================================"
puts ""

# Neu may ban dung py thay vi python thi sua dong nay thanh:
# set PYTHON_CMD py
set PYTHON_CMD python

# Chon du lieu khoa
puts "Chon du lieu khoa:"
puts "  1. Nhap p, q tu ban phim, Python tinh N/e/d/R/R2"
puts "  2. Dung du lieu co san tu tb/rsa1024_vectors.vh"
puts "  3. Thoat"
puts -nonewline {Chon [1/2/3]: }
flush stdout
gets stdin key_choice

if {$key_choice == "3"} {
    puts "Thoat run_encrypt.do."
    return
}

if {$key_choice == "1"} {
    puts ""
    puts "Nhap p, q dang decimal hoac hex."
    puts "Vi du hex: 0xABCDEF..."

    puts -nonewline {Nhap p: }
    flush stdout
    gets stdin p_value

    puts -nonewline {Nhap q: }
    flush stdout
    gets stdin q_value

    puts -nonewline {Nhap e [Enter = 65537]: }
    flush stdout
    gets stdin e_value

    if {$e_value == ""} {
        set e_value 65537
    }

    puts ""
    puts "Nhap message can encrypt:"
    puts -nonewline {Message: }
    flush stdout
    gets stdin message_text

    puts ""
    puts "Dang tao tham so encrypt tu p/q..."

    exec $PYTHON_CMD scripts/rsa2_gen_params.py encrypt --mode pq --p $p_value --q $q_value --e $e_value --message $message_text

} elseif {$key_choice == "2"} {
    puts ""
    puts "Dung vector mac dinh trong tb/rsa1024_vectors.vh."

    puts "Nhap message can encrypt:"
    puts -nonewline {Message: }
    flush stdout
    gets stdin message_text

    puts ""
    puts "Dang tao tham so encrypt tu vector mac dinh..."

    exec $PYTHON_CMD scripts/rsa2_gen_params.py encrypt --mode vector --message $message_text

} else {
    puts "Lua chon khong hop le. Thoat run_encrypt.do."
    return
}

puts ""
puts "============================================================"
puts " Compile RTL Encrypt"
puts "============================================================"

if {[file exists work]} {
    vdel -lib work -all
}
vlib work

vlog -work work +incdir+tb rtl/montgomery_multiplier.v
vlog -work work +incdir+tb rtl/rsa_modexp_mont.v
vlog -work work +incdir+tb rtl/rsa1024_top.v
vlog -work work +incdir+tb rtl/pkcs1_v15_encoder.v
vlog -work work +incdir+tb rtl/rsa1024_pkcs1_encrypt_top.v
vlog -work work +incdir+tb tb/tb_fixed_encrypt.v

puts ""
puts "============================================================"
puts " Run Encrypt Simulation"
puts "============================================================"

vsim work.tb_fixed_encrypt
run -all

puts ""
puts "============================================================"
puts " Encrypt simulation finished."
puts " Hay copy dong CIPHERTEXT_HEX de dung cho decrypt."
puts "============================================================"