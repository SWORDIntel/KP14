#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// --- Type Definitions for Clarity ---
typedef uint8_t  BYTE; // 8-bit unsigned integer
typedef uint16_t WORD; // 16-bit unsigned integer

// --- JPEG Marker Constants ---
#define SOI_MARKER  0xFFD8 // Start of Image
#define EOI_MARKER  0xFFD9 // End of Image
#define APP0_MARKER 0xFFE0 // Application-specific
#define DQT_MARKER  0xFFDB // Define Quantization Table
#define SOF0_MARKER 0xFFC0 // Start of Frame (Baseline DCT)
#define DHT_MARKER  0xFFC4 // Define Huffman Table
#define SOS_MARKER  0xFFDA // Start of Scan

// --- Helper Function to read a 16-bit big-endian value ---
// JPEG files use big-endian byte order, so we may need to swap bytes
// if our system is little-endian (most modern systems are).
WORD read_word_big_endian(FILE *file) {
    BYTE buffer[2];
    fread(buffer, 2, 1, file);
    return (buffer[0] << 8) | buffer[1];
}

// --- Structure to hold image information ---
typedef struct {
    WORD height;
    WORD width;
    int num_components;
} JpegInfo;

// --- Function Prototypes ---
void parse_sof0(FILE *file, JpegInfo *info);
void parse_dqt(FILE *file);
void parse_dht(FILE *file);

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <jpeg_file>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Error opening file");
        return 1;
    }
    
    printf("--- JPEG Parser Phase 1: C Implementation ---\n");
    printf("Parsing file: %s\n\n", argv[1]);

    JpegInfo jpeg_info = {0};
    WORD marker;

    // 1. Check for Start of Image (SOI) marker
    marker = read_word_big_endian(file);
    if (marker != SOI_MARKER) {
        fprintf(stderr, "Error: Not a valid JPEG file. Missing SOI marker.\n");
        fclose(file);
        return 1;
    }
    printf("Found SOI marker (0x%X) - Start of Image\n", SOI_MARKER);

    // 2. Loop through the file segments
    while(1) {
        // Find the next marker (starts with 0xFF)
        BYTE marker_start;
        fread(&marker_start, 1, 1, file);
        if (marker_start != 0xFF) {
            continue; // Not a marker, skip
        }
        
        BYTE marker_type;
        fread(&marker_type, 1, 1, file);
        
        // Handle standalone markers
        if (marker_type == 0xD8 || (marker_type >= 0xD0 && marker_type <= 0xD7)) {
            continue;
        }

        // Handle End of Image
        if (marker_type == EOI_MARKER & 0xFF) {
            printf("Found EOI marker (0x%X) - End of Image\n", EOI_MARKER);
            break;
        }

        printf("----------------------------------------\n");
        printf("Found Marker: 0xFF%X\n", marker_type);

        // Read the length of the segment
        WORD length = read_word_big_endian(file);
        printf("  Segment Length: %u bytes\n", length);

        // Position to skip over this segment after parsing
        long next_segment_pos = ftell(file) + length - 2;

        // 3. Parse specific segments of interest
        switch(0xFF00 | marker_type) {
            case SOF0_MARKER:
                parse_sof0(file, &jpeg_info);
                break;
            case DQT_MARKER:
                parse_dqt(file);
                break;
            case DHT_MARKER:
                parse_dht(file);
                break;
            case SOS_MARKER:
                printf("  Found SOS (Start of Scan). Compressed data follows.\n");
                printf("  Stopping parse here for Phase 1.\n");
                goto end_loop; // Exit the loop since image data starts now
            default:
                printf("  Skipping unhandled marker.\n");
                break;
        }

        // Move file pointer to the start of the next segment
        fseek(file, next_segment_pos, SEEK_SET);
    }

end_loop:
    printf("\n--- Parsing Complete ---\n");
    fclose(file);
    return 0;
}

void parse_sof0(FILE *file, JpegInfo *info) {
    printf("  Parsing SOF0 (Start of Frame)...\n");
    BYTE precision = 0;
    fread(&precision, 1, 1, file);
    info->height = read_word_big_endian(file);
    info->width = read_word_big_endian(file);
    fread(&info->num_components, 1, 1, file);

    printf("    Image Dimensions: %u x %u\n", info->width, info->height);
    printf("    Number of Components: %d\n", info->num_components);
    printf("    Precision: %d bits/sample\n", precision);
}

void parse_dqt(FILE *file) {
    printf("  Parsing DQT (Define Quantization Table)...\n");
    // For this phase, we just acknowledge its presence.
    // A full implementation would read the table data.
    printf("    (Quantization table data is present but not displayed)\n");
}

void parse_dht(FILE *file) {
    printf("  Parsing DHT (Define Huffman Table)...\n");
    // For this phase, we just acknowledge its presence.
    // A full implementation would read the code lengths and values.
    printf("    (Huffman table data is present but not displayed)\n");
}
