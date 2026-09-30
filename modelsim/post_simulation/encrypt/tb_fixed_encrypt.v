`timescale 1ns/1ps
`include "cli_encrypt_params.vh"

module tb_fixed_encrypt;

    localparam MESSAGE_BYTES = `CLI_MESSAGE_BYTES;

    localparam [MESSAGE_BYTES*8-1:0] MSG = `CLI_MSG_VALUE;

    localparam [1023:0] RSA_N  = `CLI_N_VALUE;
    localparam [1023:0] RSA_E  = `CLI_E_VALUE;
    localparam [1023:0] RSA_D  = `CLI_D_VALUE;
    localparam [1023:0] RSA_R  = `CLI_R_VALUE;
    localparam [1023:0] RSA_R2 = `CLI_R2_VALUE;

    localparam [1023:0] EXPECTED_CIPHERTEXT = `CLI_EXPECTED_C_VALUE;

    reg clk;
    reg rst_n;
    reg start;

    wire [1023:0] ciphertext;
    wire busy;
    wire done;
    wire encode_error;

    integer cycles;

    // ============================================================
    // DUT
    // Post-simulation uses RSA2.vo, so DO NOT override parameter here.
    // The RSA2.vo file itself must be generated with MESSAGE_BYTES = 34.
    // ============================================================
    rsa1024_pkcs1_encrypt_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .message(MSG),
        .public_exponent(RSA_E),
        .modulus_n(RSA_N),
        .r_mod_n(RSA_R),
        .r2_mod_n(RSA_R2),
        .ciphertext(ciphertext),
        .busy(busy),
        .done(done),
        .encode_error(encode_error)
    );

    // Clock period = 22 ns
    initial clk = 1'b0;
    always #11 clk = ~clk;

    // Count latency cycles
    always @(posedge clk) begin
        if (!rst_n || start) begin
            cycles <= 0;
        end else if (busy) begin
            cycles <= cycles + 1;
        end
    end

    initial begin
        rst_n  = 1'b0;
        start  = 1'b0;
        cycles = 0;

        $display("============================================================");
        $display(" RSA-1024 PKCS#1 ENCRYPT TESTBENCH");
        $display("============================================================");
        $display("MESSAGE_BYTES = %0d", MESSAGE_BYTES);
        $display("PLAINTEXT_ASCII = %0s", MSG);
        $display("PLAINTEXT_HEX   = %0h", MSG);
        $display("============================================================");

        // Reset
        repeat (5) @(negedge clk);
        rst_n = 1'b1;
        repeat (2) @(negedge clk);

        // Check encoder before start
        if (encode_error) begin
            $display("ERROR: encode_error = 1");
            $display("Reason may be MESSAGE_BYTES too large or PKCS#1 padding invalid.");
            $finish;
        end

        // Start pulse, 1 clock cycle
        @(negedge clk);
        start = 1'b1;
        @(negedge clk);
        start = 1'b0;

        // Wait until encryption is done
        wait(done === 1'b1);
        @(posedge clk);

        $display("");
        $display("========================================================================");
        $display(" RTL / POST-SIM ENCRYPT RESULT");
        $display("========================================================================");
        $display("");
        $display("--- THONG TIN MESSAGE ---");
        $display("MESSAGE_BYTES     : %0d", MESSAGE_BYTES);
        $display("PLAINTEXT_ASCII   : %0s", MSG);
        $display("PLAINTEXT_HEX     : %0h", MSG);
        $display("");

        $display("--- THONG TIN KHOA ---");
        $display("N_HEX             : %0256h", RSA_N);
        $display("");
        $display("E_HEX             : %0256h", RSA_E);
        $display("");
        $display("D_HEX             : %0256h", RSA_D);
        $display("");

        $display("--- THONG TIN MONTGOMERY ---");
        $display("R_HEX             : %0256h", RSA_R);
        $display("");
        $display("R2_HEX            : %0256h", RSA_R2);
        $display("");

        $display("--- KET QUA ENCRYPT ---");
        $display("CIPHERTEXT_HEX    : %0256h", ciphertext);
        $display("");
        $display("EXPECTED_CIPHER   : %0256h", EXPECTED_CIPHERTEXT);
        $display("");
        $display("LATENCY_CYCLES    : %0d", cycles);
        $display("");

        if (ciphertext === EXPECTED_CIPHERTEXT) begin
            $display("RESULT            : PASS");
        end else begin
            $display("RESULT            : FAIL");
        end

        $display("========================================================================");

        $finish;
    end

endmodule