# reporting.py
# Handles formatting and output of analysis results.

import json

def format_static_analysis_results_text(analysis_data, filepath):
    """
    Formats static analysis results into a human-readable text block.

    Args:
        analysis_data (dict): A dictionary containing results from static_analyzer.py.
                              Expected keys: 'pe_info', 'strings', 'disassembly'.
        filepath (str): The path to the file that was analyzed.

    Returns:
        str: A formatted string containing the analysis report.
    """
    report_lines = []
    report_lines.append(f"Static Analysis Report for: {filepath}")
    report_lines.append("=" * (28 + len(filepath))) # Match title length

    if not analysis_data:
        report_lines.append("\n[!] No static analysis data provided or analysis failed.")
        return "\n".join(report_lines)

    # PE Information
    pe_info = analysis_data.get('pe_info')
    if pe_info:
        report_lines.append("\n--- PE Information ---")
        report_lines.append(f"  Architecture: {pe_info.get('architecture', 'N/A')}")
        report_lines.append(f"  Entry Point: {pe_info.get('entry_point', 'N/A')}")

        report_lines.append("  Sections:")
        if pe_info.get('sections'):
            for section in pe_info['sections']:
                report_lines.append(
                    f"    - Name: {section.get('name', 'N/A')}, "
                    f"VA: {section.get('virtual_address', 'N/A')}, "
                    f"VSize: {section.get('virtual_size', 'N/A')}, "
                    f"RawSize: {section.get('raw_size', 'N/A')}"
                )
        else:
            report_lines.append("    No section data found.")

        report_lines.append("  Imports:")
        if pe_info.get('imports'):
            for dll, funcs in pe_info['imports'].items():
                report_lines.append(f"    - {dll}:")
                for func_count, func in enumerate(funcs):
                    if func_count < 5: # Display first 5 functions per DLL
                        report_lines.append(f"      - {func}")
                    elif func_count == 5:
                        report_lines.append(f"      ... and {len(funcs) - 5} more.")
                        break
        else:
            report_lines.append("    No import data found.")

        report_lines.append("  Exports:")
        if pe_info.get('exports'):
            for exp_count, exp in enumerate(pe_info['exports']):
                if exp_count < 10: # Display first 10 exports
                     report_lines.append(f"    - Name: {exp.get('name', 'N/A')}, Address: {exp.get('address', 'N/A')}")
                elif exp_count == 10:
                    report_lines.append(f"      ... and {len(pe_info['exports']) - 10} more.")
                    break
        else:
            report_lines.append("    No export data found.")
    else:
        report_lines.append("\n--- PE Information ---")
        report_lines.append("  [!] PE information extraction failed or not applicable.")

    # Extracted Strings
    strings_found = analysis_data.get('strings')
    report_lines.append("\n--- Extracted Strings (Top 20) ---")
    if strings_found:
        for i, s in enumerate(strings_found[:20]):
            report_lines.append(f"  - "{s}"")
        if len(strings_found) > 20:
            report_lines.append(f"  ... and {len(strings_found) - 20} more strings.")
    else:
        report_lines.append("  No strings found or extraction failed.")

    # Disassembled Entry Point
    disassembly = analysis_data.get('disassembly')
    report_lines.append("\n--- Entry Point Disassembly (First 20 instructions) ---")
    if disassembly:
        for instruction in disassembly:
            report_lines.append(f"  {instruction}")
    else:
        report_lines.append("  No disassembly available or extraction failed.")

    report_lines.append("\n" + "=" * 50)
    return "\n".join(report_lines)

def save_json_report(data, output_filepath):
    """
    Saves the provided data as a JSON file.

    Args:
        data (dict): The data to save.
        output_filepath (str): The path where the JSON file will be saved.
    """
    try:
        with open(output_filepath, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"JSON report saved to {output_filepath}") # Or use logger
    except IOError as e:
        print(f"Error saving JSON report to {output_filepath}: {e}") # Or use logger
    except TypeError as e:
        print(f"Error serializing data to JSON: {e}") # Or use logger


if __name__ == '__main__':
    # Example Usage
    mock_analysis_data = {
        'pe_info': {
            'architecture': '64-bit',
            'entry_point': '0x140001000',
            'sections': [{'name': '.text', 'virtual_address': '0x1000', 'virtual_size': '0x1234', 'raw_size': 4096}],
            'imports': {'kernel32.dll': ['ExitProcess', 'CreateFileA'], 'user32.dll': ['MessageBoxA']},
            'exports': [{'name': 'MyFunction', 'address': '0x140002000'}]
        },
        'strings': ['Hello World', 'This is a test string', 'Another string'] * 10,
        'disassembly': [
            '0x140001000:	push	rbp',
            '0x140001001:	mov	rbp, rsp',
            '0x140001004:	sub	rsp, 0x20'
        ]
    }

    text_report = format_static_analysis_results_text(mock_analysis_data, "/path/to/analyzed/file.exe")
    print(text_report)

    # To test JSON saving:
    # save_json_report(mock_analysis_data, "static_analysis_report.json")
    # print("\nMock JSON report saved to static_analysis_report.json (if uncommented).")

    empty_report = format_static_analysis_results_text({}, "/path/to/analyzed/file.exe")
    print(empty_report)

    failed_pe_report = format_static_analysis_results_text({'strings': [], 'disassembly': []}, "file.txt")
    print(failed_pe_report)
