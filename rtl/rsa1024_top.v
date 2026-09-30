// -----------------------------------------------------------------------------
// RSA-1024 top module.
// This block performs the RSA primitive: output = input_block^exponent mod N.
// For PKCS#1, feed `input_block` with a 1024-bit PKCS#1 encoded block EM.
// -----------------------------------------------------------------------------
module rsa1024_top (
    input  wire          clk,
    input  wire          rst_n,
    input  wire          start,

    input  wire [1023:0] input_block,
    input  wire [1023:0] exponent,
    input  wire [1023:0] modulus_n,
    input  wire [1023:0] r_mod_n,
    input  wire [1023:0] r2_mod_n,

    output wire [1023:0] output_block,
    output wire          busy,
    output wire          done
);

    rsa_modexp_mont #(
        .WIDTH(1024),
        .WORD_W(128)
    ) u_rsa_modexp_mont (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .base(input_block),
        .exponent(exponent),
        .modulus(modulus_n),
        .r_mod_n(r_mod_n),
        .r2_mod_n(r2_mod_n),
        .result(output_block),
        .busy(busy),
        .done(done)
    );

endmodule
