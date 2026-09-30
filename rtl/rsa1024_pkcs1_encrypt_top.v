// -----------------------------------------------------------------------------
// RSA-1024 PKCS#1 v1.5 encryption wrapper for lab demonstration.
// Encodes a fixed-size message into a PKCS#1 v1.5 block, then computes:
// ciphertext = EM^e mod N
// -----------------------------------------------------------------------------
module rsa1024_pkcs1_encrypt_top #(
    parameter MESSAGE_BYTES = 34
)(
    input  wire                         clk,
    input  wire                         rst_n,
    input  wire                         start,
    input  wire [MESSAGE_BYTES*8-1:0]   message,
    input  wire [1023:0]                public_exponent,
    input  wire [1023:0]                modulus_n,
    input  wire [1023:0]                r_mod_n,
    input  wire [1023:0]                r2_mod_n,
    output wire [1023:0]                ciphertext,
    output wire                         busy,
    output wire                         done,
    output wire                         encode_error
);
    wire [1023:0] encoded_block;

    pkcs1_v15_encoder #(
        .WIDTH(1024),
        .MESSAGE_BYTES(MESSAGE_BYTES)
    ) u_pkcs1_v15_encoder (
        .message(message),
        .encoded_block(encoded_block),
        .error(encode_error)
    );

    rsa1024_top u_rsa1024_top (
        .clk(clk),
        .rst_n(rst_n),
        .start(start & ~encode_error),
        .input_block(encoded_block),
        .exponent(public_exponent),
        .modulus_n(modulus_n),
        .r_mod_n(r_mod_n),
        .r2_mod_n(r2_mod_n),
        .output_block(ciphertext),
        .busy(busy),
        .done(done)
    );
endmodule
