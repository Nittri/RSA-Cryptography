
`timescale 1ns / 1ps

module rsa_system_tb;
    reg clk, rst, start;
    reg [17:0] p, q, message;
    wire [17:0] ciphertext, decrypted;
    wire done_encrypt, done_decrypt;

    rsa_system uut (
        .clk(clk), .rst(rst), .start(start),
        .p(p), .q(q), .message(message),
        .ciphertext(ciphertext), .decrypted(decrypted),
        .done_encrypt(done_encrypt), .done_decrypt(done_decrypt)
    );

    always #5 clk = ~clk;

    initial begin
        $dumpfile("rsa_wave.vcd");
        $dumpvars(0, rsa_system_tb);

        clk = 0;
        rst = 1;
        start = 0;
        p = 0; q = 0; message = 0;

        repeat (2) @(posedge clk);
        rst = 0;

        p = 59; q = 53; message = 1234;
        
        $display("Waiting for key generation to complete (1000 cycles)...");
        repeat (1000) @(posedge clk);
        $display("Key generation complete. Starting transaction.");

        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;

        wait (done_decrypt == 1);

        $display("P: %d, Q: %d, N: %d", p, q, p*q);
        $display("Original Message: %d", message);
        $display("Encrypted Ciphertext: %d", ciphertext);
        $display("Decrypted Message: %d", decrypted);

        if (decrypted == message) begin
            $display("RSA Test Passed!");
        end else begin
            $display("RSA Test Failed!");
        end

        #10 $finish;
    end
endmodule