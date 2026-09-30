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

    reg clk;
    reg rst_n;
    reg start;
    wire [1023:0] ciphertext;
    wire busy;
    wire done;
    wire encode_error;
    integer cycles;

    rsa1024_pkcs1_encrypt_top #(
        .MESSAGE_BYTES(MESSAGE_BYTES)
    ) dut (
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

        if (encode_error) begin
            $display("ERROR: PKCS1 encode_error asserted");
            $finish;
        end

        @(negedge clk);
        start = 1'b1;
        @(negedge clk);
        start = 1'b0;

        wait(done === 1'b1);
        @(posedge clk);

        $display("================ ENCRYPT DONE ================");
        $display("MESSAGE_BYTES=%0d", MESSAGE_BYTES);
        $display("===============================================");
        $display("PLAINTEXT_ASCII=%0s", MSG);
		$display("===============================================");
        $display("PLAINTEXT_HEX=%0h", MSG);
		$display("===============================================");
        $display("N_HEX=%0256h", RSA_N);
		$display("===============================================");
        $display("E_HEX=%0256h", RSA_E);
		$display("===============================================");
        $display("D_HEX=%0256h", RSA_D);
		$display("===============================================");
        $display("CIPHERTEXT_HEX=%0256h", ciphertext);
		$display("===============================================");
        $display("LATENCY_CYCLES=%0d", cycles);
        $display("===============================================");
        $finish;
    end
endmodule
