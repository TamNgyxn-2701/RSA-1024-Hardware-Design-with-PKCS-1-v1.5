`timescale 1ns/1ps
`include "rsa1024_vectors.vh"

module tb_rsa1024_top;
    reg clk;
    reg rst_n;
    reg start;

    reg  [1023:0] input_block;
    reg  [1023:0] exponent;
    reg  [1023:0] modulus_n;
    reg  [1023:0] r_mod_n;
    reg  [1023:0] r2_mod_n;
    wire [1023:0] output_block;
    wire busy;
    wire done;

    integer cycle_count;

    rsa1024_top dut (
        .clk(clk),
        .rst_n(rst_n),
        .start(start),
        .input_block(input_block),
        .exponent(exponent),
        .modulus_n(modulus_n),
        .r_mod_n(r_mod_n),
        .r2_mod_n(r2_mod_n),
        .output_block(output_block),
        .busy(busy),
        .done(done)
    );

    initial clk = 1'b0;
    always #5 clk = ~clk;

    always @(posedge clk) begin
        if (!rst_n || start)
            cycle_count <= 0;
        else if (busy)
            cycle_count <= cycle_count + 1;
    end

    task run_case;
        input [1023:0] in_blk;
        input [1023:0] exp_blk;
        input [1023:0] expected;
        input [8*32-1:0] name;
        begin
            @(negedge clk);
            input_block = in_blk;
            exponent    = exp_blk;
            modulus_n   = `RSA_N;
            r_mod_n     = `RSA_R;
            r2_mod_n    = `RSA_R2;
            start       = 1'b1;
            @(negedge clk);
            start       = 1'b0;

            wait(done === 1'b1);
            @(posedge clk);

            if (output_block === expected) begin
                $display("PASS %0s, cycles = %0d", name, cycle_count);
            end else begin
                $display("FAIL %0s", name);
                $display("expected = %0256h", expected);
                $display("got      = %0256h", output_block);
                $finish;
            end
        end
    endtask

    initial begin
        $dumpfile("rsa1024_top.vcd");
        $dumpvars(0, tb_rsa1024_top);

        rst_n       = 1'b0;
        start       = 1'b0;
        input_block = 0;
        exponent    = 0;
        modulus_n   = 0;
        r_mod_n     = 0;
        r2_mod_n    = 0;
        cycle_count = 0;

        repeat (5) @(negedge clk);
        rst_n = 1'b1;
        repeat (2) @(negedge clk);

        // Encryption primitive: C = EM^e mod N
        run_case(`RSA_M, `RSA_E, `RSA_C, "encrypt");

        // Decryption primitive: EM = C^d mod N
        run_case(`RSA_C, `RSA_D, `RSA_M, "decrypt");

        $display("All RSA-1024 tests passed.");
        $finish;
    end
endmodule
