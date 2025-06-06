#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// --- Type Definitions ---
typedef uint8_t  BYTE;
typedef uint16_t WORD;

// --- Data Structures ---

// Represents a node in the Huffman Tree.
// If it's a branch, 'value' is -1. If it's a leaf, 'value' holds the decoded symbol.
typedef struct HuffmanNode {
    struct HuffmanNode *left;  // Pointer for '0' bit
    struct HuffmanNode *right; // Pointer for '1' bit
    int value;                 // Decoded symbol, or -1 for internal nodes
} HuffmanNode;

// Represents the bitstream for reading compressed data.
typedef struct {
    const BYTE *data;
    int data_size;
    int byte_index;
    int bit_index;
} Bitstream;

// --- Function Prototypes ---
HuffmanNode* create_huffman_node();
void insert_huffman_code(HuffmanNode *root, WORD code, int length, BYTE value);
void destroy_huffman_tree(HuffmanNode *node);
int read_bit(Bitstream *stream);
int decode_symbol(Bitstream *stream, HuffmanNode *root);

// --- Main Program ---
int main() {
    printf("--- JPEG Parser Phase 2: C Implementation (Demonstration) ---\n\n");

    // --- 1. Mock Huffman Table Data (from a DHT segment) ---
    // This data would normally be parsed by an expanded Phase 1.
    // This is a simplified table for demonstration purposes.
    // LUMINANCE DC Table:
    // Codeword lengths: 0, 1, 5, ...
    // This means 1 code of length 2, 5 codes of length 3, etc.
    BYTE lengths[] = {0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0};
    BYTE values[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    int num_values = sizeof(values) / sizeof(values[0]);

    // --- 2. Build the Huffman Tree ---
    printf("Building Huffman tree from mock data...\n");
    HuffmanNode *root = create_huffman_node();
    WORD huffman_code = 0;
    int value_index = 0;

    for (int i = 0; i < 16; i++) { // For each code length from 1 to 16
        for (int j = 0; j < lengths[i]; j++) { // For each code of this length
            if (value_index < num_values) {
                // Insert code into the tree
                insert_huffman_code(root, huffman_code, i + 1, values[value_index]);
                huffman_code++;
                value_index++;
            }
        }
        huffman_code <<= 1;
    }
    printf("Huffman tree built successfully.\n\n");

    // --- 3. Mock Bitstream Data (from an SOS segment) ---
    // This data represents the compressed image scan.
    // Let's encode a few values to test:
    // Value 1 (code '10'), Value 4 (code '11100')
    // Bitstream: 1011100...
    BYTE scan_data[] = {0b10111000};
    Bitstream stream = {scan_data, sizeof(scan_data), 0, 7}; // Start at MSB of first byte

    // --- 4. Decode Symbols from the Stream ---
    printf("Decoding symbols from mock bitstream...\n");

    int decoded_value1 = decode_symbol(&stream, root);
    printf("Decoded first symbol: %d (Expected: 1)\n", decoded_value1);

    int decoded_value2 = decode_symbol(&stream, root);
    printf("Decoded second symbol: %d (Expected: 4)\n", decoded_value2);

    // --- 5. Clean up ---
    printf("\nCleaning up allocated memory...\n");
    destroy_huffman_tree(root);
    printf("--- Demonstration Complete ---\n");

    return 0;
}


// --- Function Implementations ---

// Creates and initializes a new Huffman node.
HuffmanNode* create_huffman_node() {
    HuffmanNode *node = (HuffmanNode*)malloc(sizeof(HuffmanNode));
    if (!node) {
        perror("Failed to allocate Huffman node");
        exit(1);
    }
    node->left = NULL;
    node->right = NULL;
    node->value = -1; // -1 indicates an internal node, not a leaf
    return node;
}

// Inserts a symbol and its corresponding code into the Huffman tree.
void insert_huffman_code(HuffmanNode *root, WORD code, int length, BYTE value) {
    HuffmanNode *current = root;
    for (int i = length - 1; i >= 0; i--) {
        int bit = (code >> i) & 1;
        if (bit == 0) { // Go left
            if (!current->left) {
                current->left = create_huffman_node();
            }
            current = current->left;
        } else { // Go right
            if (!current->right) {
                current->right = create_huffman_node();
            }
            current = current->right;
        }
    }
    current->value = value; // This is now a leaf node with the decoded value
}

// Recursively frees the memory allocated for the Huffman tree.
void destroy_huffman_tree(HuffmanNode *node) {
    if (node == NULL) return;
    destroy_huffman_tree(node->left);
    destroy_huffman_tree(node->right);
    free(node);
}

// Reads a single bit from the bitstream.
int read_bit(Bitstream *stream) {
    if (stream->byte_index >= stream->data_size) {
        return -1; // End of stream
    }

    // Extract the bit
    int bit = (stream->data[stream->byte_index] >> stream->bit_index) & 1;

    // Move to the next bit position
    stream->bit_index--;
    if (stream->bit_index < 0) {
        stream->bit_index = 7;
        stream->byte_index++;

        // Handle JPEG byte stuffing: if we find 0xFF, the next byte must not be 0x00.
        // If it is 0x00, we must skip it.
        if (stream->byte_index < stream->data_size &&
            stream->data[stream->byte_index - 1] == 0xFF &&
            stream->data[stream->byte_index] == 0x00) {
            stream->byte_index++;
        }
    }
    return bit;
}

// Decodes one symbol by traversing the Huffman tree.
int decode_symbol(Bitstream *stream, HuffmanNode *root) {
    HuffmanNode *current = root;
    while (current->value == -1) { // While it's an internal node
        int bit = read_bit(stream);
        if (bit == -1) return -1; // End of stream

        current = (bit == 0) ? current->left : current->right;

        if (current == NULL) {
            fprintf(stderr, "Error: Invalid Huffman code in stream.\n");
            return -1;
        }
    }
    return current->value;
}
