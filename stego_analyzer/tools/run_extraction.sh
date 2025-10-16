#!/bin/bash

# Create results directories
mkdir -p analysis_results/sample1
mkdir -p analysis_results/sample2
mkdir -p analysis_results/sample3

# Extract source code from all three samples
echo "Processing Sample 1..."
python keyplug_source_extractor.py -f NDA_extracted/Pictures/10000000000002EE000003B123F0F4409249C826.jpg -o analysis_results/sample1 --decompiler ghidra

echo "Processing Sample 2..."
python keyplug_source_extractor.py -f NDA_extracted/Pictures/10000000000002EE000003C0C4539E29A848DE5F.jpg -o analysis_results/sample2 --decompiler ghidra

echo "Processing Sample 3..."
python keyplug_source_extractor.py -f NDA_extracted/Pictures/10000000000002EE000003C67A1DCDCB7AEFBF3E.jpg -o analysis_results/sample3 --decompiler ghidra

# Run type propagation on the extracted code
echo "Running Type Propagation on extracted code..."
python -c "
from type_propagation import TypePropagator
import glob
import os

for sample_dir in ['analysis_results/sample1', 'analysis_results/sample2', 'analysis_results/sample3']:
    c_files = glob.glob(f'{sample_dir}/**/*.c', recursive=True)
    if c_files:
        print(f'Found {len(c_files)} C files in {sample_dir}')
        for c_file in c_files:
            print(f'Processing {c_file}...')
            tp = TypePropagator()
            try:
                with open(c_file, 'r') as f:
                    source_code = f.read()
                    
                enhanced_code = tp.propagate_types(source_code)
                
                output_file = os.path.join(os.path.dirname(c_file), 'enhanced_' + os.path.basename(c_file))
                with open(output_file, 'w') as f:
                    f.write(enhanced_code)
                    
                print(f'Enhanced code saved to {output_file}')
            except Exception as e:
                print(f'Error processing {c_file}: {e}')
"

# Use malware pattern learner on the extracted samples
echo "Running Malware Pattern Learning on samples..."
python -c "
from malware_pattern_learner import MalwarePatternLearner
import glob
import os
import json

# Initialize pattern learner
learner = MalwarePatternLearner(database_path='analysis_results/patterns.json')

# Find all analysis results
for sample_dir in ['analysis_results/sample1', 'analysis_results/sample2', 'analysis_results/sample3']:
    json_files = glob.glob(f'{sample_dir}/**/*.json', recursive=True)
    
    if json_files:
        print(f'Found {len(json_files)} JSON files in {sample_dir}')
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    analysis_results = json.load(f)
                
                print(f'Learning patterns from {json_file}...')
                learned_ids = learner.learn_from_analysis(analysis_results)
                print(f'Learned {len(learned_ids)} patterns from {json_file}')
            except Exception as e:
                print(f'Error processing {json_file}: {e}')
"

echo "Analysis complete. Results are in the analysis_results directory."
