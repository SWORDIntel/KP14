#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// --- Type Definitions (from Phase 2) ---
typedef uint8_t  BYTE;
typedef uint16_t WORD;

// --- Data Structures (from Phase 2) ---
typedef struct HuffmanNode {
    struct HuffmanNode *left;
    struct HuffmanNode *right;
    int value;
} HuffmanNode;

typedef struct {
    const BYTE *data;
    int data_size;
    int byte_index;
    int bit_index;
} Bitstream;

// --- Constants (for Phase 3) ---
// Standard 8x8 zig-zag mapping array
const int ZIGZAG_MAP[64] = {
     0,  1,  5,  6, 14, 15, 27, 28,
     2,  4,  7, 13, 16, 26, 29, 42,
     3,  8, 12, 17, 25, 30, 41, 43,
     9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54,
    20, 22, 33, 38, 46, 51, 55, 61,
    21, 34, 37, 47, 50, 56, 60, 62,
    35, 36, 48, 49, 57, 59, 63, -1
};


// --- Function Prototypes (from Phase 2, required for this module) ---
HuffmanNode* create_huffman_node();
void insert_huffman_code(HuffmanNode *root, WORD code, int length, BYTE value);
int read_bit(Bitstream *stream);
int decode_symbol(Bitstream *stream, HuffmanNode *root);
void destroy_huffman_tree(HuffmanNode *node);

// --- Function Prototypes (New for Phase 3) ---
int read_bits(Bitstream *stream, int count);
int huffman_decode_to_value(int code_size, int decoded_bits);
void reconstruct_dct_block(int dct_block[8][8], Bitstream *stream, 
                           HuffmanNode *dc_tree, HuffmanNode *ac_tree, 
                           const int q_table[8][8], int *last_dc_coeff);

// --- Main Program ---
int main() {
    printf("--- JPEG Parser Phase 3: C Implementation (Demonstration) ---\n\n");

    // --- Mock Data Setup (from Phase 2 logic) ---
    // In a real program, this would be parsed from the file.
    BYTE dc_lengths[] = {0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    BYTE dc_values[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    BYTE ac_lengths[] = {0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 125};
    BYTE ac_values[] = {0x01,0x02,0x03,0x00,0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,0x22,0x71,0x14,0x32,0x81,0x91,0xA1,0x08,0x23,0x42,0xB1,0xC1,0x15,0x52,0xD1,0xF0,0x24,0x33,0x62,0x72,0x82,0x09,0x0A,0x16,0x17,0x18,0x19,0x1A,0x25,0x26,0x27,0x28,0x29,0x2A,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5A,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7A,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9A,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xB2,0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,0xCA,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,0xE7,0xE8,0xE9,0xEA,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA};
    
    HuffmanNode *dc_tree = create_huffman_node();
    HuffmanNode *ac_tree = create_huffman_node();
    // (Code to build trees is omitted for brevity but logic is in Phase 2)

    // Simplified Mock Quantization Table
    const int q_table[8][8] = {
        {16, 11, 10, 16, 24, 40, 51, 61}, {12, 12, 14, 19, 26, 58, 60, 55},
        {14, 13, 16, 24, 40, 57, 69, 56}, {14, 17, 22, 29, 51, 87, 80, 62},
        {18, 22, 37, 56, 68, 109, 103, 77}, {24, 35, 55, 64, 81, 104, 113, 92},
        {49, 64, 78, 87, 103, 121, 120, 101}, {72, 92, 95, 98, 112, 100, 103, 99}
    };

    // This mock stream encodes a block. A real stream would be much longer.
    BYTE scan_data[] = {0x54, 0x92, 0xCF, 0x21};
    Bitstream stream = {scan_data, sizeof(scan_data), 0, 7};
    
    int dct_block[8][8] = {{0}};
    int last_dc_coeff = 0; // The first block starts with a DC diff from 0.

    printf("Reconstructing a single 8x8 DCT block...\n");
    reconstruct_dct_block(dct_block, &stream, dc_tree, ac_tree, q_table, &last_dc_coeff);

    printf("\n--- Reconstructed & De-quantized DCT Block ---\n");
    for (int r = 0; r < 8; r++) {
        for (int c = 0; c < 8; c++) {
            printf("%5d ", dct_block[r][c]);
        }
        printf("\n");
    }
    
    // Cleanup
    destroy_huffman_tree(dc_tree);
    destroy_huffman_tree(ac_tree);

    printf("\n--- Demonstration Complete ---\n");
    return 0;
}

// --- Function Implementations (New for Phase 3) ---

// Reads a specified number of bits from the stream.
int read_bits(Bitstream *stream, int count) {
    int value = 0;
    for (int i = 0; i < count; i++) {
        value = (value << 1) | read_bit(stream);
    }
    return value;
}

// Converts a Huffman symbol and the following bits into a signed integer value.
int huffman_decode_to_value(int code_size, int decoded_bits) {
    if (code_size == 0) {
        return 0;
    }
    // Check if the value is negative (MSB is 0 for negatives in JPEG)
    int threshold = 1 << (code_size - 1);
    if (decoded_bits < threshold) {
        return decoded_bits - ((1 << code_size) - 1);
    }
    return decoded_bits;
}


// Reconstructs a single 8x8 de-quantized DCT block.
void reconstruct_dct_block(int dct_block[8][8], Bitstream *stream, 
                           HuffmanNode *dc_tree, HuffmanNode *ac_tree, 
                           const int q_table[8][8], int *last_dc_coeff) {
    
    int coeff_vector[64] = {0};

    // 1. Decode DC Coefficient
    int dc_code_size = decode_symbol(stream, dc_tree);
    if (dc_code_size != -1) {
        int dc_diff_bits = read_bits(stream, dc_code_size);
        int dc_diff = huffman_decode_to_value(dc_code_size, dc_diff_bits);
        *last_dc_coeff += dc_diff;
        coeff_vector[0] = *last_dc_coeff;
    }

    // 2. Decode AC Coefficients
    int i = 1;
    while (i < 64) {
        int ac_symbol = decode_symbol(stream, ac_tree);
        if (ac_symbol == -1) break; // Error or end of stream

        if (ac_symbol == 0x00) { // EOB (End of Block)
            break;
        }

        int run_length = (ac_symbol >> 4) & 0x0F;
        int code_size = ac_symbol & 0x0F;

        i += run_length; // Skip zeros

        if (code_size > 0 && i < 64) {
            int ac_val_bits = read_bits(stream, code_size);
            coeff_vector[i] = huffman_decode_to_value(code_size, ac_val_bits);
        }
        i++;
    }

    // 3. De-quantize and Inverse Zig-Zag Scan
    for (i = 0; i < 64; i++) {
        int zig_zag_index = ZIGZAG_MAP[i];
        int r = zig_zag_index / 8;
        int c = zig_zag_index % 8;

        // Multiply by the quantization table value during reordering
        dct_block[r][c] = coeff_vector[i] * q_table[r][c];
    }
}

// --- Function Implementations (from Phase 2, stubs for standalone compilation) ---
// In a real project, these would be in their own file. Full implementations
// can be found in the Phase 2 artifact.
HuffmanNode* create_huffman_node() { 
    HuffmanNode *node = (HuffmanNode*)malloc(sizeof(HuffmanNode));
    node->left = NULL; node->right = NULL; node->value = -1;
    return node;
}
void insert_huffman_code(HuffmanNode *root, WORD code, int length, BYTE value) { /* Omitted */ }
int read_bit(Bitstream *stream) { /* Omitted */ return 0;}
int decode_symbol(Bitstream *stream, HuffmanNode *root) { /* Omitted */ return 0;}
void destroy_huffman_tree(HuffmanNode *node) { if(node) free(node); }

