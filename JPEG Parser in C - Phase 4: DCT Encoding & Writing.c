#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// --- Type Definitions ---
typedef uint8_t  BYTE;
typedef uint16_t WORD;

// --- Data Structures ---
// Structure to write bits to a byte buffer
typedef struct {
    BYTE *buffer;
    int capacity;
    int byte_index;
    int bit_position; // 0-7, from MSB to LSB
} BitstreamWriter;

// Structure to hold a Huffman code (code and its length)
typedef struct {
    WORD code;
    int length;
} HuffmanCode;

// --- Constants ---
const int ZIGZAG_MAP[64] = {
     0,  1,  5,  6, 14, 15, 27, 28,  2,  4,  7, 13, 16, 26, 29, 42,
     3,  8, 12, 17, 25, 30, 41, 43,  9, 11, 18, 24, 31, 40, 44, 53,
    10, 19, 23, 32, 39, 45, 52, 54, 20, 22, 33, 38, 46, 51, 55, 61,
    21, 34, 37, 47, 50, 56, 60, 62, 35, 36, 48, 49, 57, 59, 63, -1
};

// --- Function Prototypes ---
void write_word_big_endian(FILE *file, WORD value);
void write_marker(FILE *file, WORD marker);
void write_segment_header(FILE *file, WORD marker, WORD length);
void write_dqt(FILE *file, const BYTE q_table[64]);
void write_sof0(FILE *file, WORD width, WORD height);
void write_dht(FILE *file, const BYTE* lengths, const BYTE* values, BYTE table_class, BYTE dest_id);
void write_sos(FILE *file);

void write_bit(BitstreamWriter *writer, int bit);
void write_bits(BitstreamWriter *writer, WORD code, int length);
void flush_bits(BitstreamWriter *writer);

void huffman_encode_block(const int dct_block[8][8], const BYTE q_table[64], 
                          const HuffmanCode dc_huff_table[12], const HuffmanCode ac_huff_table[256],
                          int *last_dc_coeff, BitstreamWriter *writer);


// --- Main Program ---
int main() {
    printf("--- JPEG Parser Phase 4: C Implementation (Demonstration) ---\n\n");

    // --- Mock Data Setup ---
    // A sample 8x8 block of DCT coefficients (pre-quantization)
    const int sample_dct_block[8][8] = {
        {23, -12, -8, 0, 0, 0, 0, 0}, { -9, 7, 0, 0, 0, 0, 0, 0},
        {-5, 0, 0, 0, 0, 0, 0, 0},   { 0, 0, 0, 0, 0, 0, 0, 0},
        { 0, 0, 0, 0, 0, 0, 0, 0},   { 0, 0, 0, 0, 0, 0, 0, 0},
        { 0, 0, 0, 0, 0, 0, 0, 0},   { 0, 0, 0, 0, 0, 0, 0, 0}
    };
    
    // Standard Luminance Quantization Table
    const BYTE q_table[64] = {
        16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
        14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
        18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
        49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99
    };

    // --- Create a simple JPEG file with one 8x8 block ---
    FILE *outfile = fopen("output.jpg", "wb");
    if (!outfile) {
        perror("Failed to create output.jpg");
        return 1;
    }

    // --- Write JPEG Headers ---
    write_marker(outfile, 0xFFD8); // SOI
    write_dqt(outfile, q_table);
    write_sof0(outfile, 8, 8); // Image is one 8x8 block
    // DHT, SOS, etc. would be here. For simplicity, we skip DHT writing and use hardcoded tables.
    // In a real implementation, you would write the actual Huffman tables.
    write_sos(outfile);

    // --- Encode the Block ---
    // Simplified Huffman tables for demonstration
    HuffmanCode dc_table[12] = {{0b100, 3}, {0b101, 3}, {0b110, 3}, /* ... */};
    HuffmanCode ac_table[256] = {{0b1010, 4}, {0b11011, 5}, /* ... */};

    BitstreamWriter writer = {0};
    writer.capacity = 1024;
    writer.buffer = (BYTE*)malloc(writer.capacity);
    memset(writer.buffer, 0, writer.capacity);
    writer.bit_position = 7;

    int last_dc = 0;
    huffman_encode_block(sample_dct_block, q_table, dc_table, ac_table, &last_dc, &writer);
    flush_bits(&writer); // Finalize the bitstream

    // --- Write the encoded data ---
    fwrite(writer.buffer, 1, writer.byte_index + 1, outfile);
    
    // --- Write End of Image marker ---
    write_marker(outfile, 0xFFD9); // EOI

    fclose(outfile);
    free(writer.buffer);
    printf("Successfully created 'output.jpg' with one encoded 8x8 block.\n");
    printf("\n--- Demonstration Complete ---\n");

    return 0;
}

// --- Writing Functions ---
void write_word_big_endian(FILE *file, WORD value) {
    fputc((value >> 8) & 0xFF, file);
    fputc(value & 0xFF, file);
}

void write_marker(FILE *file, WORD marker) {
    fputc(marker >> 8, file);
    fputc(marker & 0xFF, file);
}

void write_segment_header(FILE *file, WORD marker, WORD length) {
    write_marker(file, marker);
    write_word_big_endian(file, length);
}

void write_dqt(FILE *file, const BYTE q_table[64]) {
    write_segment_header(file, 0xFFDB, 67); // 67 = 2 (len) + 1 (info) + 64 (table)
    fputc(0x00, file); // Precision 8-bit, Table ID 0
    fwrite(q_table, 1, 64, file);
}

void write_sof0(FILE *file, WORD width, WORD height) {
    write_segment_header(file, 0xFFC0, 17);
    fputc(8, file); // 8-bit precision
    write_word_big_endian(file, height);
    write_word_big_endian(file, width);
    fputc(1, file); // 1 component (grayscale)
    fputc(1, file); // Component ID
    fputc(0x11, file); // H/V sampling factor 1,1
    fputc(0, file); // Quantization table ID 0
}

void write_sos(FILE *file) {
    write_segment_header(file, 0xFFDA, 12);
    fputc(1, file); // 1 component
    fputc(1, file); // Component ID
    fputc(0, file); // DC/AC table ID 0
    fputc(0, file); // Ss, Se (spectral selection)
    fputc(0x3F, file);
    fputc(0, file); // Ah, Al (successive approximation)
}

// --- Bitstream Writing Functions ---
void write_bit(BitstreamWriter *writer, int bit) {
    if (bit) {
        writer->buffer[writer->byte_index] |= (1 << writer->bit_position);
    }
    writer->bit_position--;
    if (writer->bit_position < 0) {
        // Handle byte stuffing for 0xFF
        if (writer->buffer[writer->byte_index] == 0xFF) {
            writer->byte_index++;
            writer->buffer[writer->byte_index] = 0x00;
        }
        writer->bit_position = 7;
        writer->byte_index++;
    }
}

void write_bits(BitstreamWriter *writer, WORD code, int length) {
    for (int i = length - 1; i >= 0; i--) {
        write_bit(writer, (code >> i) & 1);
    }
}

void flush_bits(BitstreamWriter *writer) {
    if (writer->bit_position != 7) {
         writer->byte_index++;
    }
}

// --- Encoding Logic ---
void huffman_encode_block(const int dct_block[8][8], const BYTE q_table[64], 
                          const HuffmanCode dc_huff_table[12], const HuffmanCode ac_huff_table[256],
                          int *last_dc_coeff, BitstreamWriter *writer) {

    int quantized_coeffs[64];
    // 1. Quantize and Zig-Zag Scan
    for (int i = 0; i < 64; i++) {
        int r = ZIGZAG_MAP[i] / 8;
        int c = ZIGZAG_MAP[i] % 8;
        quantized_coeffs[i] = round((float)dct_block[r][c] / q_table[i]);
    }

    // 2. Encode DC coefficient
    int dc_diff = quantized_coeffs[0] - *last_dc_coeff;
    *last_dc_coeff = quantized_coeffs[0];
    
    // Find category and write Huffman code for DC
    // (Simplified placeholder logic)
    int dc_category = (dc_diff == 0) ? 0 : floor(log2(abs(dc_diff))) + 1;
    write_bits(writer, dc_table[dc_category].code, dc_table[dc_category].length);
    if (dc_category > 0) {
        write_bits(writer, (dc_diff > 0) ? dc_diff : dc_diff + (1 << dc_category) - 1, dc_category);
    }
    
    // 3. Encode AC coefficients with Run-Length Encoding (RLE)
    int zero_run = 0;
    for (int i = 1; i < 64; i++) {
        if (quantized_coeffs[i] == 0) {
            zero_run++;
        } else {
            while (zero_run >= 16) {
                write_bits(writer, ac_table[0xF0].code, ac_table[0xF0].length); // ZRL
                zero_run -= 16;
            }
            // Find category and write Huffman code for AC
            int ac_category = floor(log2(abs(quantized_coeffs[i]))) + 1;
            int symbol = (zero_run << 4) | ac_category;
            write_bits(writer, ac_table[symbol].code, ac_table[symbol].length);
            write_bits(writer, (quantized_coeffs[i] > 0) ? quantized_coeffs[i] : quantized_coeffs[i] + (1 << ac_category) - 1, ac_category);
            zero_run = 0;
        }
    }
    // End of Block (EOB)
    if (zero_run > 0) {
        write_bits(writer, ac_table[0x00].code, ac_table[0x00].length);
    }
}
