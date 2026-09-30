// -----------------------------------------------------------------------------
// RSA-1024 PKCS#1 v1.5 decryption/check wrapper for lab demonstration.
// Computes: EM = ciphertext^d mod N, then checks/extracts the message.
// -----------------------------------------------------------------------------
module rsa1024_pkcs1_decrypt_top #(
    parameter MESSAGE_BYTES = 14
)(
    input  wire                         clk,
    input  wire                         rst_n,
    input  wire                         start,
    input  wire [1023:0]                ciphertext,
    input  wire [1023:0]                private_exponent,
    input  wire [1023:0]                modulus_n,
    input  wire [1023:0]                r_mod_n,
    input  wire [1023:0]                r2_mod_n,
    output wire [1023:0]                encoded_block,
    output wire [MESSAGE_BYTES*8-1:0]   message,
    output wire                         pkcs1_valid,
    output wire                         busy,
    output wire                         done
);
    rsa1024_top u_rsa1024_top (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .input_block(ciphertext),
        .exponent(private_exponent),
        .modulus_n(modulus_n),
        .r_mod_n(r_mod_n),
        .r2_mod_n(r2_mod_n),
        .output_block(encoded_block),
        .busy(busy),
        .done(done)
    );

    pkcs1_v15_checker #(
        .WIDTH(1024),
        .MESSAGE_BYTES(MESSAGE_BYTES)
    ) u_pkcs1_v15_checker (
        .encoded_block(encoded_block),
        .message(message),
        .valid(pkcs1_valid)
    );
endmodule
