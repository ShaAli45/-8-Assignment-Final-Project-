#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <bitset>
#include <cstdint>

// These are the initial hash values (H0 to H7) for SHA-256
// These constants come from the fractional parts of the square roots of the first 8 primes (2..19). 
///Preventing predictability, constants are derived form math oper(n*n of prime numbers)
///Standardization. SHA-265 widely uses ctyptographic diff implementations and systes to ens consitency across diff implem and sys
///sec,these val increses the ramdoness, (small change i/ signigfciat changes in o/)
const uint32_t H0 = 0x6a09e667;  // First 32 bits of sqrt(2)
const uint32_t H1 = 0xbb67ae85;  // First 32 bits of sqrt(3)
const uint32_t H2 = 0x3c6ef372;  // First 32 bits of sqrt(5)
const uint32_t H3 = 0xa54ff53a;  // First 32 bits of sqrt(7)
const uint32_t H4 = 0x510e527f;  // First 32 bits of sqrt(11)
const uint32_t H5 = 0x9b05688c;  // First 32 bits of sqrt(13)
const uint32_t H6 = 0x1f83d9ab;  // First 32 bits of sqrt(17)
const uint32_t H7 = 0x5be0cd19;  // First 32 bits of sqrt(19)

// SHA-256 uses 64 constant values (K) derived from the fractional parts of the cube roots of the first 64 primes (2..311).
// These constants are used in the main loop of the algorithm, they intruduces additiona randomness and complex
///Each are a 32-bit word
///It ensures the constants are pseudo-random, this also helps to strengthen the sec of the algorithm
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Padding the message to make its length a multiple of 512 bits
///tp process messages, so that can be properly hashed using thr SHA-256 algo
///input message is conveted into vector 
std::vector<uint8_t> padMessage(const std::string &input) {
    
    std::vector<uint8_t> paddedMessage(input.begin(), input.end());

    // Append a '1' bit (0x80 in hex) to the message. This is always done.
    ///SHA pading starts by appending single "1" bit to the message
    ///this marks the padding begines 
    paddedMessage.push_back(0x80);

    // Append '0' bits until the message length is 448 bits mod 512
    while (paddedMessage.size() % 64 != 56) {
        paddedMessage.push_back(0x00);
    }

    // Append the length of the original message (in bits) as a 64-bit big-endian integer.
    // This represents the total length of the original message before padding.
    uint64_t originalLengthBits = input.size() * 8;
    for (int i = 7; i >= 0; --i) {
        paddedMessage.push_back((originalLengthBits >> (i * 8)) & 0xFF);
    }

    return paddedMessage; ////this function returnf fully padded messages now and ready to process the SHA algo 
}

// Processing each 512-bit block of the message
void processBlock(const std::vector<uint8_t> &block, uint32_t &a, uint32_t &b, uint32_t &c, uint32_t &d, uint32_t &e, uint32_t &f, uint32_t &g, uint32_t &h) {
    uint32_t W[64];

    // Step 1: Break the 512-bit block into sixteen 32-bit words
    for (int i = 0; i < 16; ++i) {
        W[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }

    // Step 2: Extend the first 16 words into 48 more words, making 64 total words in the message schedule
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = (W[i-15] >> 7) | (W[i-15] << (32 - 7)) ^ (W[i-15] >> 18) ^ (W[i-15] >> 3);
        uint32_t s1 = (W[i-2] >> 17) | (W[i-2] << (32 - 17)) ^ (W[i-2] >> 19) ^ (W[i-2] >> 10);
        W[i] = W[i-16] + s0 + W[i-7] + s1;
    }

    //step: 3 Initialize working variables with the current hash values
    uint32_t temp_a = a, temp_b = b, temp_c = c, temp_d = d;
    uint32_t temp_e = e, temp_f = f, temp_g = g, temp_h = h;

    // step:4 Perform the main hash computation loop (64 rounds)
    for (int i = 0; i < 64; ++i) {
        // Calculate S1, the choice function ch, and the first temporary value
        uint32_t S1 = (temp_e >> 6) | (temp_e << (32 - 6)) ^ (temp_e >> 11) ^ (temp_e >> 25);
        uint32_t ch = (temp_e & temp_f) ^ (~temp_e & temp_g);
        uint32_t temp1 = temp_h + S1 + ch + K[i] + W[i];

        // Calculate S0, the majority function maj, and the second temporary value
        uint32_t S0 = (temp_a >> 2) | (temp_a << (32 - 2)) ^ (temp_a >> 13) ^ (temp_a >> 22);
        uint32_t maj = (temp_a & temp_b) ^ (temp_a & temp_c) ^ (temp_b & temp_c);
        uint32_t temp2 = S0 + maj;

        //step 5:  Update the working variables
        temp_h = temp_g;
        temp_g = temp_f;
        temp_f = temp_e;
        temp_e = temp_d + temp1;
        temp_d = temp_c;
        temp_c = temp_b;
        temp_b = temp_a;
        temp_a = temp1 + temp2;
    }

    // Add the working variables back to the current hash values
    a += temp_a;
    b += temp_b;
    c += temp_c;
    d += temp_d;
    e += temp_e;
    f += temp_f;
    g += temp_g;
    h += temp_h;
}

int main() {
    // Step 1: Read the entire Book of Mark from a file
    std::ifstream file("mark.txt");
    if (!file) {
        std::cerr << "Error: File 'mark.txt' not found!" << std::endl;
        return 1; // Exit the program with an error code
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string message = buffer.str();

    // Step 2: Pad the message to make it a multiple of 512 bits
    std::vector<uint8_t> paddedMessage = padMessage(message);

    // Initialize hash values (a through h) with the initial hash constants
    uint32_t a = H0, b = H1, c = H2, d = H3;
    uint32_t e = H4, f = H5, g = H6, h = H7;

    // Step 3: Process the padded message in 512-bit chunks
    for (size_t i = 0; i < paddedMessage.size(); i += 64) {
        std::vector<uint8_t> block(paddedMessage.begin() + i, paddedMessage.begin() + i + 64);
        processBlock(block, a, b, c, d, e, f, g, h);
    }

    // Output the final hash value
    std::cout << std::hex << std::setfill('0');
    std::cout << "SHA-256 Hash of Book of Mark will be: " << std::setw(8) << a << std::setw(8) << b << std::setw(8) << c << std::setw(8) << d
              << std::setw(8) << e << std::setw(8) << f << std::setw(8) << g << std::setw(8) << h << std::endl;

    return 0;
}
