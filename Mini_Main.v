module Mini_Div(input [17:0] a, input [17:0] b, output reg [17:0] x, output reg [17:0] y);
    integer i;
    reg [18:0] rem;

    always @(*) begin
        rem = 0;
        x = 0;
        for (i = 17; i >= 0; i = i - 1) begin
            rem = (rem << 1) | a[i];
            rem = rem - b;
            if (rem[18]) begin
                rem = rem + b;
                x[i] = 0;
            end else begin
                x[i] = 1;
            end
        end
        y = rem[17:0];
    end
endmodule


module mod_exp (input wire clk, rst, start,input wire [17:0] base, exp, mod,output reg [17:0] result,output reg done);
    reg [35:0] b, r;
    reg [17:0] e, m;
    reg [1:0] state;

    localparam IDLE = 0, CALC = 1, DONE = 2;

    always @(posedge clk or posedge rst)
    begin
        if (rst) 
        begin
            state <= IDLE; result <= 0; done <= 0;
        end 
        else 
        begin
            case (state)
                IDLE: if (start) 
                begin
                    b <= base % mod; e <= exp; m <= mod; r <= 1;
                    done <= 0; state <= CALC;
                end
                CALC: 
                begin
                    if (e == 0) 
                    begin
                        result <= r;
                        state <= DONE;
                    end 
                    else 
                    begin
                        if (e[0]) r <= (r * b) % m;
                        e <= e >> 1;
                        b <= (b * b) % m;
                    end
                end
                DONE: 
                begin
                    done <= 1;
                    state <= IDLE;
                end
            endcase
        end
    end
endmodule


module modinv (
    input wire clk, rst, start,
    input wire [17:0] e, phi,
    output reg [17:0] d,
    output reg done
);
    reg [17:0] a, b, x0, x1, temp;
    reg [2:0] state;
    reg [17:0] div_a, div_b;
    wire [17:0] q, r;

    Mini_Div divider (.a(div_a), .b(div_b), .x(q), .y(r));

    localparam IDLE = 0, INIT = 1, CALC = 2, WAIT_DIV = 3, UPDATE = 4, DONE = 5;

    always @(posedge clk or posedge rst) begin
        if (rst) begin
            state <= IDLE; done <= 0; d <= 0;
            a <= 0; b <= 0; x0 <= 0; x1 <= 0; temp <= 0;
        end else begin
            case (state)
                IDLE: if (start) begin
                    a <= phi; b <= e;
                    x0 <= 0; x1 <= 1;
                    done <= 0;
                    state <= INIT;
                end
                INIT: state <= (b == 0) ? DONE : CALC;
                CALC: begin
                    div_a <= a; div_b <= b;
                    state <= WAIT_DIV;
                end
                WAIT_DIV: begin
                    temp <= x0 - q * x1;
                    state <= UPDATE;
                end
                UPDATE: begin
                    a <= b; b <= r;
                    x0 <= x1; x1 <= temp;
                    state <= (r == 0) ? DONE : CALC;
                end
                DONE: begin
                    d <= (x0[17]) ? x0 + phi : x0;
                    done <= 1;
                    state <= IDLE;
                end
            endcase
        end
    end
endmodule


module rsa_encryptor (
    input wire clk, rst, start,
    input wire [17:0] message, e, n,
    output wire [17:0] ciphertext,
    output wire done
);
    mod_exp modexp_inst (
        .clk(clk), .rst(rst), .start(start),
        .base(message), .exp(e), .mod(n),
        .result(ciphertext), .done(done)
    );
endmodule

module rsa_decryptor (
    input wire clk, rst, start,
    input wire [17:0] ciphertext, d, n,
    output wire [17:0] message,
    output wire done
);
    mod_exp modexp_inst (
        .clk(clk), .rst(rst), .start(start),
        .base(ciphertext), .exp(d), .mod(n),
        .result(message), .done(done)
    );
endmodule


module rsa_system (input wire clk, rst, start,input wire [17:0] p, q, message,output wire [17:0] ciphertext, decrypted,output wire done_encrypt, done_decrypt);
    reg [17:0] n, phi;
    wire [17:0] e = 3;
    wire [17:0] d;
    wire done_keygen;

    reg start_keygen_reg, start_encrypt_reg, start_decrypt_reg;
    reg [2:0] state;
    localparam S_IDLE = 0,S_CALC_CONST = 1,S_KEYGEN_START = 2,S_KEYGEN_WAIT  = 3, S_ENC_START = 4,S_ENC_WAIT = 5,S_DEC_START = 6,S_DEC_WAIT= 7;
    
    always @(posedge clk or posedge rst) 
    begin
        if (rst) 
        begin
            state <= S_IDLE;
            n <= 0; phi <= 0;
            start_keygen_reg <= 0;
            start_encrypt_reg <= 0;
            start_decrypt_reg <= 0;
        end 
        else 
        begin
            start_keygen_reg <= 0;
            start_encrypt_reg <= 0;
            start_decrypt_reg <= 0;
            
            case (state)
                S_IDLE: 
                begin
                    if (start) 
                    begin
                        state <= S_CALC_CONST;
                    end
                end
                
                S_CALC_CONST: 
                begin
                    n <= p * q;
                    phi <= (p - 1) * (q - 1);
                    state <= S_KEYGEN_START;
                end
                
                S_KEYGEN_START: 
                begin
                    start_keygen_reg <= 1;
                    state <= S_KEYGEN_WAIT;
                end
                
                S_KEYGEN_WAIT: 
                begin
                    if (done_keygen) 
                    begin
                        state <= S_ENC_START;
                    end
                end
                
                S_ENC_START: 
                begin
                    start_encrypt_reg <= 1;
                    state <= S_ENC_WAIT;
                end
                
                S_ENC_WAIT: 
                begin
                    if (done_encrypt) 
                    begin
                        state <= S_DEC_START;
                    end
                end
                
                S_DEC_START: 
                begin
                    start_decrypt_reg <= 1;
                    state <= S_DEC_WAIT;
                end

                S_DEC_WAIT: 
                begin
                    if (done_decrypt) 
                    begin
                        state <= S_IDLE;
                    end
                end
            endcase
        end
    end
    modinv keygen (.clk(clk), .rst(rst), .start(start_keygen_reg), .e(e), .phi(phi), .d(d), .done(done_keygen));
    rsa_encryptor encrypt (.clk(clk), .rst(rst), .start(start_encrypt_reg), .message(message), .e(e), .n(n), .ciphertext(ciphertext), .done(done_encrypt));
    rsa_decryptor decrypt (.clk(clk), .rst(rst), .start(start_decrypt_reg), .ciphertext(ciphertext), .d(d), .n(n), .message(decrypted), .done(done_decrypt));
endmodule