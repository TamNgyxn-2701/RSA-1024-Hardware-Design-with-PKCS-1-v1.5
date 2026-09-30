// -----------------------------------------------------------------------------
// PKCS#1 v1.5 encoded-message checker for fixed message size.
// Checks: EM = 0x00 || 0x02 || PS || 0x00 || M
// where PS bytes must be non-zero and at least 8 bytes long.
// -----------------------------------------------------------------------------
module pkcs1_v15_checker #(
    parameter WIDTH = 1024,
    parameter MESSAGE_BYTES = 14
)(
    input  wire [WIDTH-1:0]           encoded_block,
    output reg  [MESSAGE_BYTES*8-1:0] message,
    output reg                        valid
);
    localparam K_BYTES  = WIDTH / 8;
    localparam PS_BYTES = K_BYTES - MESSAGE_BYTES - 3;
    localparam SEP_POS  = K_BYTES - MESSAGE_BYTES - 1;

    integer i;
    reg [7:0] b;

    always @(*) begin
        valid = 1'b1;
        message = {MESSAGE_BYTES*8{1'b0}};

        if ((WIDTH % 8) != 0 || MESSAGE_BYTES <= 0 || PS_BYTES < 8) begin
            valid = 1'b0;
        end

        // Check leading bytes.
        if (encoded_block[(K_BYTES-1)*8 +: 8] != 8'h00) valid = 1'b0;
        if (encoded_block[(K_BYTES-2)*8 +: 8] != 8'h02) valid = 1'b0;

        // Check PS bytes are non-zero.
        for (i = 2; i < SEP_POS; i = i + 1) begin
            b = encoded_block[(K_BYTES - 1 - i)*8 +: 8];
            if (b == 8'h00) valid = 1'b0;
        end

        // Check separator.
        if (encoded_block[(K_BYTES - 1 - SEP_POS)*8 +: 8] != 8'h00) valid = 1'b0;

        // Extract message.
        for (i = SEP_POS + 1; i < K_BYTES; i = i + 1) begin
            message[(K_BYTES - 1 - i)*8 +: 8] = encoded_block[(K_BYTES - 1 - i)*8 +: 8];
        end
    end
endmodule
