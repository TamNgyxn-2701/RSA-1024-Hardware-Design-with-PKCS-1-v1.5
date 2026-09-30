`timescale 1ns/1ps
`include "cli_decrypt_params.vh"

module tb_fixed_decrypt;
    localparam MESSAGE_BYTES = `CLI_MESSAGE_BYTES;

    localparam [1023:0] RSA_N  = `CLI_N_VALUE;
    localparam [1023:0] RSA_D  = `CLI_D_VALUE;
    localparam [1023:0] RSA_R  = `CLI_R_VALUE;
    localparam [1023:0] RSA_R2 = `CLI_R2_VALUE;
    localparam [1023:0] CIPHER = `CLI_C_VALUE;

    reg clk;
    reg rst_n;
    reg start;
    wire [1023:0] encoded_block;
    wire [MESSAGE_BYTES*8-1:0] message;
    wire pkcs1_valid;
    wire busy;
    wire done;
    integer cycles;

    rsa1024_pkcs1_decrypt_top #(
        .MESSAGE_BYTES(MESSAGE_BYTES)
    ) dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .ciphertext(CIPHER),
        .private_exponent(RSA_D),
        .modulus_n(RSA_N),
        .r_mod_n(RSA_R),
        .r2_mod_n(RSA_R2),
        .encoded_block(encoded_block),
        .message(message),
        .pkcs1_valid(pkcs1_valid),
        .busy(busy),
        .done(done)
    );

    initial clk = 1'b0;
    always #11 clk = ~clk;  // period 22 ns, khop SDC 45.45 MHz

    always @(posedge clk) begin
        if (!rst_n || start)
            cycles <= 0;
        else if (busy)
            cycles <= cycles + 1;
    end

    initial begin
        rst_n = 1'b0;
        start = 1'b0;
        cycles = 0;

        repeat (5) @(negedge clk);
        rst_n = 1'b1;
        repeat (2) @(negedge clk);

        @(negedge clk);
        start = 1'b1;
        @(negedge clk);
        start = 1'b0;

        wait(done === 1'b1);
        @(posedge clk);

        $display("================ DECRYPT DONE ================");
        $display("MESSAGE_BYTES=%0d", MESSAGE_BYTES);
		$display("===============================================");
        $display("PKCS1_VALID=%0d", pkcs1_valid);
		$display("===============================================");
        $display("EM_HEX=%0256h", encoded_block);
		$display("===============================================");
        $display("PLAINTEXT_HEX=%0h", message);
		$display("===============================================");
        $display("PLAINTEXT_ASCII=%0s", message);
		$display("===============================================");
        $display("LATENCY_CYCLES=%0d", cycles);
        $display("===============================================");
        if (pkcs1_valid !== 1'b1)
            $display("WARNING: PKCS1_VALID = 0. Sai C, sai d, sai N, hoac MESSAGE_BYTES khong dung.");
        $finish;
    end
endmodule
