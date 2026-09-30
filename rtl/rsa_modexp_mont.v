// -----------------------------------------------------------------------------
// RSA modular exponentiation using Montgomery multiplication.
// Computes: result = base^exponent mod modulus.
//
// Inputs r_mod_n and r2_mod_n are precomputed outside the core:
//   r_mod_n  = 2^WIDTH mod modulus
//   r2_mod_n = 2^(2*WIDTH) mod modulus
//
// This core expects `base` to be the PKCS#1 encoded block EM when used for
// encryption/signature primitive. PKCS#1 padding/encoding can be handled in
// software or testbench before the RSA core.
// -----------------------------------------------------------------------------
module rsa_modexp_mont #(
    parameter WIDTH  = 1024,
    // Width of the word-serial Montgomery datapath.
    parameter WORD_W = 128
)(
    input  wire             clk,
    input  wire             rst_n,
    input  wire             start,

    input  wire [WIDTH-1:0] base,
    input  wire [WIDTH-1:0] exponent,
    input  wire [WIDTH-1:0] modulus,
    input  wire [WIDTH-1:0] r_mod_n,
    input  wire [WIDTH-1:0] r2_mod_n,

    output reg  [WIDTH-1:0] result,
    output reg              busy,
    output reg              done
);

    function integer clog2;
        input integer value;
        integer i;
        begin
            value = value - 1;
            for (i = 0; value > 0; i = i + 1)
                value = value >> 1;
            clog2 = i;
        end
    endfunction

    localparam IDX_W = clog2(WIDTH);
    localparam S_IDLE          = 4'd0;
    localparam S_CONV_START    = 4'd1;
    localparam S_CONV_WAIT     = 4'd2;
    localparam S_LOOP_START_SQ = 4'd3;
    localparam S_LOOP_WAIT_SQ  = 4'd4;
    localparam S_LOOP_START_M  = 4'd5;
    localparam S_LOOP_WAIT_M   = 4'd6;
    localparam S_NEXT_BIT      = 4'd7;
    localparam S_FINAL_START   = 4'd8;
    localparam S_FINAL_WAIT    = 4'd9;
    localparam S_DONE          = 4'd10;

    reg [3:0] state;
    reg [WIDTH-1:0] base_reg, exp_reg, mod_reg, r_reg, r2_reg;
    reg [WIDTH-1:0] base_mont;
    reg [WIDTH-1:0] x_mont;
    reg [IDX_W-1:0] bit_index;

    reg              mont_start;
    reg [WIDTH-1:0] mont_A, mont_B;
    wire [WIDTH-1:0] mont_result;
    wire             mont_busy;
    wire             mont_done;

    montgomery_multiplier #(
        .WIDTH(WIDTH),
        .WORD_W(WORD_W)
    ) u_montgomery_multiplier (
        .clk(clk),
        .rst_n(rst_n),
        .start(mont_start),
        .A(mont_A),
        .B(mont_B),
        .N(mod_reg),
        .result(mont_result),
        .busy(mont_busy),
        .done(mont_done)
    );

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            result     <= {WIDTH{1'b0}};
            busy       <= 1'b0;
            done       <= 1'b0;
            mont_start <= 1'b0;
            mont_A     <= {WIDTH{1'b0}};
            mont_B     <= {WIDTH{1'b0}};
            base_reg   <= {WIDTH{1'b0}};
            exp_reg    <= {WIDTH{1'b0}};
            mod_reg    <= {WIDTH{1'b0}};
            r_reg      <= {WIDTH{1'b0}};
            r2_reg     <= {WIDTH{1'b0}};
            base_mont  <= {WIDTH{1'b0}};
            x_mont     <= {WIDTH{1'b0}};
            bit_index  <= {IDX_W{1'b0}};
        end else begin
            done       <= 1'b0;
            mont_start <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        base_reg  <= base;
                        exp_reg   <= exponent;
                        mod_reg   <= modulus;
                        r_reg     <= r_mod_n;
                        r2_reg    <= r2_mod_n;
                        x_mont    <= r_mod_n;          // Montgomery value of 1
                        bit_index <= WIDTH-1;
                        busy      <= 1'b1;
                        state     <= S_CONV_START;
                    end
                end

                // base_mont = MontMul(base, R^2 mod N) = base * R mod N
                S_CONV_START: begin
                    mont_A     <= base_reg;
                    mont_B     <= r2_reg;
                    mont_start <= 1'b1;
                    state      <= S_CONV_WAIT;
                end

                S_CONV_WAIT: begin
                    if (mont_done) begin
                        base_mont <= mont_result;
                        state     <= S_LOOP_START_SQ;
                    end
                end

                // x = MontMul(x, x)
                S_LOOP_START_SQ: begin
                    mont_A     <= x_mont;
                    mont_B     <= x_mont;
                    mont_start <= 1'b1;
                    state      <= S_LOOP_WAIT_SQ;
                end

                S_LOOP_WAIT_SQ: begin
                    if (mont_done) begin
                        x_mont <= mont_result;
                        if (exp_reg[bit_index]) begin
                            state <= S_LOOP_START_M;
                        end else begin
                            state <= S_NEXT_BIT;
                        end
                    end
                end

                // if exponent bit is 1: x = MontMul(x, base_mont)
                S_LOOP_START_M: begin
                    mont_A     <= x_mont;
                    mont_B     <= base_mont;
                    mont_start <= 1'b1;
                    state      <= S_LOOP_WAIT_M;
                end

                S_LOOP_WAIT_M: begin
                    if (mont_done) begin
                        x_mont <= mont_result;
                        state  <= S_NEXT_BIT;
                    end
                end

                S_NEXT_BIT: begin
                    if (bit_index == 0) begin
                        state <= S_FINAL_START;
                    end else begin
                        bit_index <= bit_index - 1'b1;
                        state     <= S_LOOP_START_SQ;
                    end
                end

                // Convert out of Montgomery domain: result = MontMul(x, 1)
                S_FINAL_START: begin
                    mont_A     <= x_mont;
                    mont_B     <= {{(WIDTH-1){1'b0}}, 1'b1};
                    mont_start <= 1'b1;
                    state      <= S_FINAL_WAIT;
                end

                S_FINAL_WAIT: begin
                    if (mont_done) begin
                        result <= mont_result;
                        state  <= S_DONE;
                    end
                end

                S_DONE: begin
                    done  <= 1'b1;
                    busy  <= 1'b0;
                    state <= S_IDLE;
                end

                default: begin
                    state <= S_IDLE;
                end
            endcase
        end
    end

endmodule
