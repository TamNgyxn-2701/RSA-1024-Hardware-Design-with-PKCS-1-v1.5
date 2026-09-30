# ============================================================
# run_post_encrypt.do
# RSA2 Encrypt - Post-Timing Simulation
#
# Required files in the SAME folder:
#   RSA2.vo
#   RSA2_v.sdo
#   tb_fixed_encrypt.v
#   cli_encrypt_params.vh
#
# Notes:
# - RSA2.vo was generated with MESSAGE_BYTES = 14.
# - cli_encrypt_params.vh must use CLI_MESSAGE_BYTES = 14
#   and CLI_MSG_VALUE must be 112'h...
# ============================================================

transcript on

puts ""
puts "============================================================"
puts " RSA2 Encrypt - Post-Timing Simulation"
puts "============================================================"

# Chuyển thư mục làm việc về nơi chứa file .do
set DO_DIR [file dirname [info script]]
if {$DO_DIR != "." && $DO_DIR != ""} {
    cd $DO_DIR
}

puts "Current directory:"
pwd

# Kiểm tra các file bắt buộc
foreach f {RSA2.vo RSA2_v.sdo tb_fixed_encrypt.v cli_encrypt_params.vh} {
    if {![file exists $f]} {
        puts "ERROR: Missing required file: $f"
        puts "Put $f in the same folder as run_post_encrypt.do"
        quit -code 1
    }
}

# Xóa và tạo lại thư viện work
if {[file exists work]} {
    vdel -lib work -all
}
vlib work
vmap work work

puts ""
puts "============================================================"
puts " Compile gate-level netlist"
puts "============================================================"

# Compile netlist sau Quartus
vlog -work work RSA2.vo

puts ""
puts "============================================================"
puts " Compile testbench"
puts "============================================================"

# +incdir+. để ModelSim tìm được cli_encrypt_params.vh trong thư mục hiện tại
vlog -work work +incdir+. tb_fixed_encrypt.v

puts ""
puts "============================================================"
puts " Run simulation with SDF slow corner"
puts "============================================================"

# Gắn SDF vào đúng instance /tb_fixed_encrypt/dut
vsim -t ps -L altera_ver -L lpm_ver -L sgate_ver -L cycloneii_ver \
     -sdfmax /tb_fixed_encrypt/dut=RSA2_v.sdo \
     work.tb_fixed_encrypt

# Hàm thêm wave an toàn.
# Nếu tín hiệu không tồn tại thì chỉ báo skip, không làm dừng simulation.
proc safe_add_wave {args} {
    if {[catch {eval add wave $args} err]} {
        puts "Wave skip: $err"
    }
}

safe_add_wave -divider "TB Control"
safe_add_wave sim:/tb_fixed_encrypt/clk
safe_add_wave sim:/tb_fixed_encrypt/rst_n
safe_add_wave sim:/tb_fixed_encrypt/start
safe_add_wave sim:/tb_fixed_encrypt/busy
safe_add_wave sim:/tb_fixed_encrypt/done
safe_add_wave sim:/tb_fixed_encrypt/encode_error
safe_add_wave sim:/tb_fixed_encrypt/cycles

safe_add_wave -divider "RSA Input/Output"
safe_add_wave -radix hexadecimal sim:/tb_fixed_encrypt/dut/message
safe_add_wave -radix hexadecimal sim:/tb_fixed_encrypt/dut/public_exponent
safe_add_wave -radix hexadecimal sim:/tb_fixed_encrypt/dut/modulus_n
safe_add_wave -radix hexadecimal sim:/tb_fixed_encrypt/ciphertext

safe_add_wave -divider "All TB Signals"
safe_add_wave -r sim:/tb_fixed_encrypt/*

run -all

puts ""
puts "============================================================"
puts " Post encrypt simulation finished."
puts " Check Transcript for CIPHERTEXT_HEX and LATENCY_CYCLES."
puts "============================================================"