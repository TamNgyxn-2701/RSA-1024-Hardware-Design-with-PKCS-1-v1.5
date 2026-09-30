module montgomery_multiplier #(
    parameter WIDTH  = 1024,
    // Word-serial datapath width. Use 128-bit words instead of 32-bit words.
    parameter WORD_W = 128
)(
    input  wire             clk,
    input  wire             rst_n,
    input  wire             start,
    input  wire [WIDTH-1:0] A,
    input  wire [WIDTH-1:0] B,
    input  wire [WIDTH-1:0] N,
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

    localparam TOTAL_W    = WIDTH + 2;
    localparam WORDS      = (TOTAL_W + WORD_W - 1) / WORD_W;
    localparam PAD_W      = WORDS * WORD_W;
    localparam CNT_W      = clog2(WIDTH + 1);
    localparam WORD_CNT_W = clog2(WORDS);

    localparam S_IDLE       = 4'd0;
    localparam S_ITER_START = 4'd1;
    localparam S_ADD_A_INIT = 4'd2;
    localparam S_ADD_N_INIT = 4'd3;
    localparam S_ADD_RUN    = 4'd4;
    localparam S_CHECK_Q    = 4'd5;
    localparam S_SHIFT      = 4'd6;
    localparam S_CMP_INIT   = 4'd7;
    localparam S_CMP_RUN    = 4'd8;
    localparam S_SUB_INIT   = 4'd9;
    localparam S_SUB_RUN    = 4'd10;
    localparam S_OUTPUT     = 4'd11;
    localparam S_DONE       = 4'd12;

    reg [3:0] state;

    reg [WIDTH-1:0] A_reg;
    reg [WIDTH-1:0] B_reg;
    reg [WIDTH-1:0] N_reg;

    // T is padded to a multiple of WORD_W to simplify word addressing.
    reg [PAD_W-1:0] T;

    reg [CNT_W-1:0]      bit_count;
    reg [WORD_CNT_W-1:0] word_index;

    reg add_sel_n;     // 0: add A, 1: add N
    reg add_carry;
    reg sub_borrow;
    reg cmp_gt;
    reg cmp_lt;

    wire [PAD_W-1:0] A_ext;
    wire [PAD_W-1:0] N_ext;

    assign A_ext = {{(PAD_W-WIDTH){1'b0}}, A_reg};
    assign N_ext = {{(PAD_W-WIDTH){1'b0}}, N_reg};

    // Temporary variables used inside the clocked process.
    reg [WORD_W-1:0] t_word;
    reg [WORD_W-1:0] op_word;
    reg [WORD_W:0]   add_tmp;
    reg [WORD_W:0]   sub_tmp;
    reg              cmp_gt_next;
    reg              cmp_lt_next;

    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state      <= S_IDLE;
            result     <= {WIDTH{1'b0}};
            busy       <= 1'b0;
            done       <= 1'b0;
            A_reg      <= {WIDTH{1'b0}};
            B_reg      <= {WIDTH{1'b0}};
            N_reg      <= {WIDTH{1'b0}};
            T          <= {PAD_W{1'b0}};
            bit_count  <= {CNT_W{1'b0}};
            word_index <= {WORD_CNT_W{1'b0}};
            add_sel_n  <= 1'b0;
            add_carry  <= 1'b0;
            sub_borrow <= 1'b0;
            cmp_gt     <= 1'b0;
            cmp_lt     <= 1'b0;
        end else begin
            done <= 1'b0;

            case (state)
                S_IDLE: begin
                    busy <= 1'b0;
                    if (start) begin
                        A_reg      <= A;
                        B_reg      <= B;
                        N_reg      <= N;
                        T          <= {PAD_W{1'b0}};
                        bit_count  <= {CNT_W{1'b0}};
                        word_index <= {WORD_CNT_W{1'b0}};
                        add_carry  <= 1'b0;
                        sub_borrow <= 1'b0;
                        cmp_gt     <= 1'b0;
                        cmp_lt     <= 1'b0;
                        busy       <= 1'b1;
                        state      <= S_ITER_START;
                    end
                end

                // One Montgomery bit iteration starts here.
                // Original algorithm:
                //   if B[0] == 1: T = T + A
                //   if T[0] == 1: T = T + N
                //   T = T >> 1
                //   B = B >> 1
                S_ITER_START: begin
                    if (B_reg[0]) begin
                        state <= S_ADD_A_INIT;
                    end else begin
                        state <= S_CHECK_Q;
                    end
                end

                S_ADD_A_INIT: begin
                    add_sel_n  <= 1'b0;
                    add_carry  <= 1'b0;
                    word_index <= {WORD_CNT_W{1'b0}};
                    state      <= S_ADD_RUN;
                end

                S_ADD_N_INIT: begin
                    add_sel_n  <= 1'b1;
                    add_carry  <= 1'b0;
                    word_index <= {WORD_CNT_W{1'b0}};
                    state      <= S_ADD_RUN;
                end

                // Word-serial addition: T = T + A_ext or T = T + N_ext.
                S_ADD_RUN: begin
                    t_word = T[word_index*WORD_W +: WORD_W];
                    if (add_sel_n)
                        op_word = N_ext[word_index*WORD_W +: WORD_W];
                    else
                        op_word = A_ext[word_index*WORD_W +: WORD_W];

                    add_tmp = {1'b0, t_word} + {1'b0, op_word} + {{WORD_W{1'b0}}, add_carry};
                    T[word_index*WORD_W +: WORD_W] <= add_tmp[WORD_W-1:0];
                    add_carry <= add_tmp[WORD_W];

                    if (word_index == WORDS-1) begin
                        if (add_sel_n)
                            state <= S_SHIFT;
                        else
                            state <= S_CHECK_Q;
                    end else begin
                        word_index <= word_index + 1'b1;
                    end
                end

                // q = T[0] after optional T+A. If q=1, add N before shifting.
                S_CHECK_Q: begin
                    if (T[0])
                        state <= S_ADD_N_INIT;
                    else
                        state <= S_SHIFT;
                end

                S_SHIFT: begin
                    T     <= T >> 1;
                    B_reg <= B_reg >> 1;

                    if (bit_count == WIDTH-1) begin
                        state <= S_CMP_INIT;
                    end else begin
                        bit_count <= bit_count + 1'b1;
                        state     <= S_ITER_START;
                    end
                end

                // Final reduction: if T >= N then T = T - N.
                // The comparison is done word by word from MSW to LSW.
                S_CMP_INIT: begin
                    word_index <= WORDS-1;
                    cmp_gt     <= 1'b0;
                    cmp_lt     <= 1'b0;
                    state      <= S_CMP_RUN;
                end

                S_CMP_RUN: begin
                    t_word = T[word_index*WORD_W +: WORD_W];
                    op_word = N_ext[word_index*WORD_W +: WORD_W];

                    cmp_gt_next = cmp_gt;
                    cmp_lt_next = cmp_lt;

                    if (!cmp_gt && !cmp_lt) begin
                        if (t_word > op_word)
                            cmp_gt_next = 1'b1;
                        else if (t_word < op_word)
                            cmp_lt_next = 1'b1;
                    end

                    cmp_gt <= cmp_gt_next;
                    cmp_lt <= cmp_lt_next;

                    if (word_index == 0) begin
                        if (!cmp_lt_next)
                            state <= S_SUB_INIT;   // equal or greater
                        else
                            state <= S_OUTPUT;     // already smaller than N
                    end else begin
                        word_index <= word_index - 1'b1;
                    end
                end

                S_SUB_INIT: begin
                    word_index <= {WORD_CNT_W{1'b0}};
                    sub_borrow <= 1'b0;
                    state      <= S_SUB_RUN;
                end

                // Word-serial subtraction: T = T - N_ext.
                S_SUB_RUN: begin
                    t_word = T[word_index*WORD_W +: WORD_W];
                    op_word = N_ext[word_index*WORD_W +: WORD_W];

                    sub_tmp = {1'b0, t_word} - {1'b0, op_word} - {{WORD_W{1'b0}}, sub_borrow};
                    T[word_index*WORD_W +: WORD_W] <= sub_tmp[WORD_W-1:0];
                    sub_borrow <= sub_tmp[WORD_W];

                    if (word_index == WORDS-1) begin
                        state <= S_OUTPUT;
                    end else begin
                        word_index <= word_index + 1'b1;
                    end
                end

                S_OUTPUT: begin
                    result <= T[WIDTH-1:0];
                    state  <= S_DONE;
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
