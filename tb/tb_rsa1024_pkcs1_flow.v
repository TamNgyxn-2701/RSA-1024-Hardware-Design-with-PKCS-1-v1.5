`timescale 1ns/1ps
`include "rsa1024_vectors.vh"

module tb_rsa1024_pkcs1_flow;
    localparam MESSAGE_BYTES = 14;
    localparam [MESSAGE_BYTES*8-1:0] MSG = "HELLO RSA 1024";

    reg clk;
    reg rst_n;
    reg start_enc;
    reg start_dec;

    wire [1023:0] ciphertext;
    wire enc_busy;
    wire enc_done;
    wire enc_error;

    wire [1023:0] decrypted_em;
    wire [MESSAGE_BYTES*8-1:0] decrypted_msg;
    wire pkcs1_valid;
    wire dec_busy;
    wire dec_done;

    integer cycle_count;

    rsa1024_pkcs1_encrypt_top #(
        .MESSAGE_BYTES(MESSAGE_BYTES)
    ) u_encrypt (
        .clk(clk),
        .rst_n(rst_n),
        .start(start_enc),
        .message(MSG),
        .public_exponent(`RSA_E),
        .modulus_n(`RSA_N),
        .r_mod_n(`RSA_R),
        .r2_mod_n(`RSA_R2),
        .ciphertext(ciphertext),
        .busy(enc_busy),
        .done(enc_done),
        .encode_error(enc_error)
    );

    rsa1024_pkcs1_decrypt_top #(
        .MESSAGE_BYTES(MESSAGE_BYTES)
    ) u_decrypt (
        .clk(clk),
        .rst_n(rst_n),
        .start(start_dec),
        .ciphertext(ciphertext),
        .private_exponent(`RSA_D),
        .modulus_n(`RSA_N),
        .r_mod_n(`RSA_R),
        .r2_mod_n(`RSA_R2),
        .encoded_block(decrypted_em),
        .message(decrypted_msg),
        .pkcs1_valid(pkcs1_valid),
        .busy(dec_busy),
        .done(dec_done)
    );

    initial clk = 1'b0;
    always #5 clk = ~clk;

    always @(posedge clk) begin
        if (!rst_n || start_enc || start_dec)
            cycle_count <= 0;
        else if (enc_busy || dec_busy)
            cycle_count <= cycle_count + 1;
    end

    initial begin
        $dumpfile("rsa1024_pkcs1_flow.vcd");
        $dumpvars(0, tb_rsa1024_pkcs1_flow);

        rst_n = 1'b0;
        start_enc = 1'b0;
        start_dec = 1'b0;
        cycle_count = 0;

        repeat (5) @(negedge clk);
        rst_n = 1'b1;
        repeat (2) @(negedge clk);

        // 1) PKCS#1 encode + RSA encryption
        if (enc_error) begin
            $display("FAIL encode_error asserted");
            $finish;
        end

        @(negedge clk);
        start_enc = 1'b1;
        @(negedge clk);
        start_enc = 1'b0;
        wait(enc_done === 1'b1);
        @(posedge clk);

        if (ciphertext !== `RSA_C) begin
            $display("FAIL encrypt wrapper");
            $display("expected = %0256h", `RSA_C);
            $display("got      = %0256h", ciphertext);
            $finish;
        end
        $display("PASS PKCS#1 encode + RSA encrypt, cycles = %0d", cycle_count);

        // 2) RSA decryption + PKCS#1 check/extract
        @(negedge clk);
        start_dec = 1'b1;
        @(negedge clk);
        start_dec = 1'b0;
        wait(dec_done === 1'b1);
        @(posedge clk);

        if (decrypted_em !== `RSA_M) begin
            $display("FAIL decrypt wrapper EM");
            $display("expected = %0256h", `RSA_M);
            $display("got      = %0256h", decrypted_em);
            $finish;
        end

        if (pkcs1_valid !== 1'b1) begin
            $display("FAIL PKCS#1 check");
            $finish;
        end

        if (decrypted_msg !== MSG) begin
            $display("FAIL message extract");
            $display("expected = %0s", MSG);
            $display("got      = %0s", decrypted_msg);
            $finish;
        end

        $display("PASS RSA decrypt + PKCS#1 check/extract, cycles = %0d", cycle_count);
        $display("All complete RSA-1024 PKCS#1 flow tests passed.");
        $finish;
    end
endmodule
