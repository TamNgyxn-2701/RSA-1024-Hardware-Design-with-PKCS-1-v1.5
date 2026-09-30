// -----------------------------------------------------------------------------
// PKCS#1 v1.5 encoded-message generator for RSA-1024 encryption demo.
//
// EM = 0x00 || 0x02 || PS || 0x00 || M
// where PS is a non-zero padding string.
//
// This module is synthesizable and deterministic for lab/simulation purposes.
// For real cryptographic use, PS must be generated from a cryptographically
// secure random source and must be different for each encryption.
// -----------------------------------------------------------------------------
module pkcs1_v15_encoder #(
    parameter WIDTH = 1024,
    parameter MESSAGE_BYTES = 14
)(
    input  wire [MESSAGE_BYTES*8-1:0] message,
    output reg  [WIDTH-1:0]           encoded_block,
    output reg                        error
);
    localparam K_BYTES  = WIDTH / 8;
    localparam PS_BYTES = K_BYTES - MESSAGE_BYTES - 3;
    localparam SEP_POS  = K_BYTES - MESSAGE_BYTES - 1;

    integer i;
    reg [7:0] b;

    always @(*) begin
        encoded_block = {WIDTH{1'b0}};
        error = 1'b0;

        // PKCS#1 v1.5 requires at least 8 bytes of PS.
        if ((WIDTH % 8) != 0 || MESSAGE_BYTES <= 0 || PS_BYTES < 8) begin
            error = 1'b1;
        end

        for (i = 0; i < K_BYTES; i = i + 1) begin
            if (i == 0) begin
                b = 8'h00;
            end else if (i == 1) begin
                b = 8'h02;
            end else if (i < SEP_POS) begin
                // Deterministic non-zero padding for simulation: 01, 02, ..., FF, 01...
                b = ((i - 2) % 255) + 1;
            end else if (i == SEP_POS) begin
                b = 8'h00;
            end else begin
                // Copy message MSB byte first into the end of the encoded block.
                b = message[(K_BYTES - 1 - i)*8 +: 8];
            end

            encoded_block[(K_BYTES - 1 - i)*8 +: 8] = b;
        end
    end
endmodule
