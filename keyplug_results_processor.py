#!/usr/bin/env python3
"""
KEYPLUG Results Processor
-------------------------
Handles aggregation, formatting, and saving of analysis results.
Provides mechanisms for passing results between analysis modules
and generating consolidated reports.
"""

import os
import json
import time
import traceback
from datetime import datetime
from typing import Dict, List, Any, Optional
from collections import defaultdict
import hashlib


class ResultsProcessor:
    """
    Manages the collection, processing, and reporting of analysis results.
    Provides mechanisms for modules to share data and generate final reports.
    """
    
    def __init__(self, base_output_dir: str):
        """
        Initialize the results processor.
        
        Args:
            base_output_dir: Base directory for saving all analysis outputs
        """
        self.base_output_dir = base_output_dir
        
        # Primary results storage
        self.file_results = defaultdict(dict)  # {filename: {component_name: result_dict}}
        self.global_results = {}  # For memory dumps, cross-sample correlation, DB updates
        
        # Analysis context for passing between components
        self.analysis_context = {}
        
        # Create output directory
        os.makedirs(base_output_dir, exist_ok=True)
    
    def register_file(self, file_path: str) -> None:
        """
        Register a file for analysis and initialize its results storage.
        
        Args:
            file_path: Path to the file being analyzed
        """
        file_name = os.path.basename(file_path)
        if file_name not in self.file_results:
            file_hash = self._calculate_file_hash(file_path)
            self.file_results[file_name] = {
                "metadata": {
                    "file_path": file_path,
                    "file_name": file_name,
                    "file_size": os.path.getsize(file_path),
                    "md5": file_hash,
                    "analysis_started": datetime.now().isoformat(),
                    "analysis_completed": None
                },
                "components": {}
            }
    
    def register_memory_dump(self, dump_path: str) -> None:
        """
        Register a memory dump for analysis.
        
        Args:
            dump_path: Path to the memory dump file
        """
        dump_name = os.path.basename(dump_path)
        self.global_results["memory_forensics"] = {
            "metadata": {
                "dump_path": dump_path,
                "dump_name": dump_name,
                "dump_size": os.path.getsize(dump_path),
                "analysis_started": datetime.now().isoformat(),
                "analysis_completed": None
            },
            "results": {}
        }
    
    def store_file_result(self, file_name: str, component_name: str, result: Dict[str, Any]) -> None:
        """
        Store results from a component for a specific file.
        
        Args:
            file_name: Name of the analyzed file
            component_name: Name of the component that produced the result
            result: Result dictionary from the component
        """
        if file_name not in self.file_results:
            raise ValueError(f"File '{file_name}' has not been registered for analysis")
        
        # Add execution timestamp
        result.setdefault("metadata", {})["processed_at"] = datetime.now().isoformat()
        
        # Store in file results
        self.file_results[file_name]["components"][component_name] = result
        
        # If this is the last component, mark analysis as completed
        self.file_results[file_name]["metadata"]["last_updated"] = datetime.now().isoformat()
    
    def store_memory_result(self, component_name: str, result: Dict[str, Any]) -> None:
        """
        Store results from memory forensics analysis.
        
        Args:
            component_name: Name of the memory analysis component
            result: Result dictionary from the component
        """
        if "memory_forensics" not in self.global_results:
            raise ValueError("Memory dump has not been registered for analysis")
        
        # Add execution timestamp
        result.setdefault("metadata", {})["processed_at"] = datetime.now().isoformat()
        
        # Store in memory results
        self.global_results["memory_forensics"]["results"][component_name] = result
        self.global_results["memory_forensics"]["metadata"]["analysis_completed"] = datetime.now().isoformat()
    
    def store_global_result(self, component_name: str, result: Dict[str, Any]) -> None:
        """
        Store results from global analysis components (e.g., cross-sample correlation).
        
        Args:
            component_name: Name of the global analysis component
            result: Result dictionary from the component
        """
        # Add execution timestamp
        result.setdefault("metadata", {})["processed_at"] = datetime.now().isoformat()
        
        # Store in global results
        self.global_results[component_name] = result
    
    def update_analysis_context(self, context_updates: Dict[str, Any]) -> None:
        """
        Update the shared analysis context that's passed between components.
        
        Args:
            context_updates: Dictionary of context updates to merge
        """
        self.analysis_context.update(context_updates)
    
    def get_analysis_context(self) -> Dict[str, Any]:
        """
        Get the current analysis context.
        
        Returns:
            The current analysis context dictionary
        """
        return self.analysis_context
    
    def get_file_component_result(self, file_name: str, component_name: str) -> Optional[Dict[str, Any]]:
        """
        Get results from a specific component for a specific file.
        
        Args:
            file_name: Name of the analyzed file
            component_name: Name of the component
            
        Returns:
            Result dictionary or None if not found
        """
        if file_name not in self.file_results:
            return None
        
        components = self.file_results[file_name].get("components", {})
        return components.get(component_name)
    
    def get_all_file_results(self, file_name: str) -> Dict[str, Any]:
        """
        Get all results for a specific file.
        
        Args:
            file_name: Name of the analyzed file
            
        Returns:
            Dictionary with all results for the file
        """
        return self.file_results.get(file_name, {})
    
    def get_memory_results(self) -> Dict[str, Any]:
        """
        Get all memory forensics results.
        
        Returns:
            Dictionary with all memory forensics results
        """
        return self.global_results.get("memory_forensics", {})
    
    def get_global_result(self, component_name: str) -> Optional[Dict[str, Any]]:
        """
        Get results from a specific global analysis component.
        
        Args:
            component_name: Name of the global analysis component
            
        Returns:
            Result dictionary or None if not found
        """
        return self.global_results.get(component_name)
    
    def save_component_result_to_file(self, file_name: str, component_name: str, 
                                     output_format: str = "json") -> str:
        """
        Save component results for a specific file to a dedicated output file.
        
        Args:
            file_name: Name of the analyzed file
            component_name: Name of the component
            output_format: Format to save in (currently supports 'json')
            
        Returns:
            Path to the saved file
        """
        result = self.get_file_component_result(file_name, component_name)
        if not result:
            raise ValueError(f"No results found for {component_name} on {file_name}")
        
        # Create component directory if needed
        component_dir = os.path.join(self.base_output_dir, component_name.lower())
        os.makedirs(component_dir, exist_ok=True)
        
        # Define output file path
        output_file = os.path.join(component_dir, f"{file_name}_{component_name}_results.json")
        
        # Save based on format
        if output_format.lower() == "json":
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
        else:
            raise ValueError(f"Unsupported output format: {output_format}")
        
        return output_file
    
    def generate_consolidated_report(self):
        """
        Generate consolidated reports in JSON and text formats.
        
        Returns:
            Dictionary with paths to the generated reports
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_data = {
            "analysis_timestamp": timestamp,
            "files_analyzed": list(self.file_results.keys()),
            "file_results": self.file_results,
            "global_results": self.global_results,
            "metadata": {
                "processor_version": "2.0.0",
                "report_generated": datetime.now().isoformat(),
                "analysis_context": self.analysis_context
            }
        }
        
        # Generate output paths for different formats
        report_paths = {
            "json": os.path.join(self.base_output_dir, f"consolidated_report_{timestamp}.json"),
            "txt": os.path.join(self.base_output_dir, f"consolidated_report_{timestamp}.txt"),
            "html": os.path.join(self.base_output_dir, f"consolidated_report_{timestamp}.html"),
            "summary": os.path.join(self.base_output_dir, f"summary_report_{timestamp}.txt"),
        }
        
        # Save JSON report
        with open(report_paths["json"], 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Save text report
        with open(report_paths["txt"], 'w') as f:
            self._write_text_report(f, report_data)
        
        # Save HTML report
        with open(report_paths["html"], 'w') as f:
            self._write_html_report(f, report_data)
        
        # Save summary report
        with open(report_paths["summary"], 'w') as f:
            self._write_summary_report(f, report_data)
        
        return report_paths
    
    def _write_text_report(self, file_handle, report_data: Dict[str, Any]) -> None:
        """
        Write a human-readable text report to the provided file handle.
        
        Args:
            file_handle: Open file handle to write to
            report_data: Complete report data dictionary
        """
        # Report header
        file_handle.write("KEYPLUG UNIFIED ANALYSIS REPORT\n")
        file_handle.write("==============================\n\n")
        
        # Metadata
        meta = report_data['report_metadata']
        file_handle.write(f"Generated: {meta['generated_at']}\n")
        file_handle.write(f"Total Files Analyzed: {meta['total_files_analyzed']}\n")
        
        openvino = meta.get('openvino_status', {})
        if openvino:
            availability = openvino.get('available', False)
            device = openvino.get('preferred_device', 'N/A')
            file_handle.write(f"OpenVINO: {'Available - Device: ' + device if availability else 'Not Available'}\n")
        
        file_handle.write(f"Total Execution Time: {meta.get('execution_time', 0):.2f} seconds\n")
        file_handle.write("\n" + "-" * 50 + "\n\n")
        
        # Global Results
        if report_data['global_analysis_results']:
            file_handle.write("GLOBAL ANALYSIS RESULTS:\n")
            file_handle.write("-----------------------\n\n")
            
            for component, results in report_data['global_analysis_results'].items():
                if component == "memory_forensics":
                    self._write_memory_results(file_handle, results)
                else:
                    # Other global components (correlation, DB updates, etc.)
                    file_handle.write(f"Component: {component}\n")
                    meta = results.get('metadata', {})
                    file_handle.write(f"  Processed: {meta.get('processed_at', 'Unknown')}\n")
                    
                    # Write component-specific highlights
                    if component == "KeyplugCrossSampleCorrelator":
                        correlations = results.get('correlations', [])
                        file_handle.write(f"  Found {len(correlations)} cross-sample correlations\n")
                        
                        # Show top correlations
                        for i, corr in enumerate(correlations[:5]):
                            file_handle.write(f"    {i+1}. {corr.get('type')}: {corr.get('description')}\n")
                    
                    elif component == "KeyplugPatternDatabase":
                        db_stats = results.get('database_stats', {})
                        file_handle.write(f"  Pattern Database Stats:\n")
                        file_handle.write(f"    Total Patterns: {db_stats.get('total_patterns', 0)}\n")
                        file_handle.write(f"    New Patterns: {db_stats.get('new_patterns', 0)}\n")
                        file_handle.write(f"    Updated Patterns: {db_stats.get('updated_patterns', 0)}\n")
                
                file_handle.write("\n")
            
            file_handle.write("-" * 50 + "\n\n")
        
        # File-Specific Results
        if report_data['file_specific_results']:
            file_handle.write("FILE-SPECIFIC ANALYSIS RESULTS:\n")
            file_handle.write("-----------------------------\n\n")
            
            for file_name, file_data in report_data['file_specific_results'].items():
                meta = file_data.get('metadata', {})
                
                file_handle.write(f"File: {file_name}\n")
                file_handle.write(f"  Size: {meta.get('file_size', 'Unknown')} bytes\n")
                file_handle.write(f"  MD5: {meta.get('md5', 'Unknown')}\n")
                file_handle.write(f"  Analysis Started: {meta.get('analysis_started', 'Unknown')}\n")
                
                # Components
                components = file_data.get('components', {})
                file_handle.write(f"  Components Analyzed: {len(components)}\n\n")
                
                # Write results for each component
                for comp_name, comp_results in components.items():
                    status = comp_results.get('status', 'Unknown')
                    exec_time = comp_results.get('execution_time_seconds', 0)
                    
                    file_handle.write(f"  {comp_name}:\n")
                    file_handle.write(f"    Status: {status}\n")
                    file_handle.write(f"    Execution Time: {exec_time:.2f} seconds\n")
                    
                    # Component-specific highlights
                    if comp_name == "AnalyzePE":
                        pe_info = comp_results.get('pe_info', {})
                        file_handle.write(f"    PE Type: {pe_info.get('type', 'Unknown')}\n")
                        file_handle.write(f"    Sections: {len(pe_info.get('sections', []))}\n")
                        file_handle.write(f"    Entry Point: {pe_info.get('entry_point', 'Unknown')}\n")
                    
                    elif comp_name == "MLMalwareAnalyzer":
                        ml_results = comp_results.get('classification', {})
                        file_handle.write(f"    Classification: {ml_results.get('top_family', 'Unknown')}\n")
                        file_handle.write(f"    Confidence: {ml_results.get('confidence', 0):.2f}\n")
                        file_handle.write(f"    Malicious Score: {ml_results.get('malicious_score', 0):.2f}\n")
                    
                    # Add more component-specific result formatting as needed
                    
                    file_handle.write("\n")
                
                file_handle.write("-" * 40 + "\n\n")
    
    def _write_memory_results(self, file_handle, memory_results: Dict[str, Any]) -> None:
        """
        Write memory forensics results to the report.
        
        Args:
            file_handle: Open file handle to write to
            memory_results: Memory forensics results dictionary
        """
        meta = memory_results.get('metadata', {})
        results = memory_results.get('results', {})
        
        file_handle.write("Memory Forensics Analysis:\n")
        file_handle.write(f"  Dump: {meta.get('dump_name', 'Unknown')}\n")
        file_handle.write(f"  Size: {meta.get('dump_size', 'Unknown')} bytes\n")
        file_handle.write(f"  Analysis Started: {meta.get('analysis_started', 'Unknown')}\n")
        file_handle.write(f"  Analysis Completed: {meta.get('analysis_completed', 'Unknown')}\n\n")
        
        # Process memory analysis results
        for component, comp_results in results.items():
            file_handle.write(f"  {component}:\n")
            
            # Extract key information
            processes = comp_results.get('processes', [])
            file_handle.write(f"    Processes: {len(processes)}\n")
            
            # Top processes by importance
            important_procs = sorted(processes, 
                                   key=lambda p: p.get('malicious_score', 0), 
                                   reverse=True)[:5]
            
            for proc in important_procs:
                file_handle.write(f"      {proc.get('pid', '?')}: {proc.get('name', 'Unknown')} "
                                f"(Score: {proc.get('malicious_score', 0):.2f})\n")
            
            # Other memory artifacts
            artifacts = comp_results.get('artifacts', {})
            if artifacts:
                file_handle.write("\n    Key Artifacts:\n")
                for category, items in artifacts.items():
                    file_handle.write(f"      {category}: {len(items)} found\n")
            
            file_handle.write("\n")
    
    def _write_html_report(self, file_handle, report_data: Dict[str, Any]) -> None:
        """
        Write an HTML report to the provided file handle.
        
        Args:
            file_handle: Open file handle to write to
            report_data: Complete report data dictionary
        """
        # HTML header with basic styling
        file_handle.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KEYPLUG Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; color: #333; }
        h1, h2, h3 { color: #0056b3; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .section { background-color: white; padding: 15px; margin-bottom: 15px; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .file-item { border-left: 3px solid #0056b3; padding-left: 10px; margin-bottom: 10px; }
        .component { margin-left: 20px; margin-bottom: 15px; border-top: 1px solid #eee; padding-top: 10px; }
        .metadata { color: #666; font-size: 0.9em; }
        .finding { background-color: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 3px; }
        .high { border-left: 3px solid #dc3545; }
        .medium { border-left: 3px solid #fd7e14; }
        .low { border-left: 3px solid #28a745; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 15px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .footer { text-align: center; margin-top: 30px; font-size: 0.8em; color: #666; }
    </style>
</head>
<body>
    <div class="container">
""")

        # Report header
        file_handle.write(f"""        <div class="header">
            <h1>KEYPLUG Malware Analysis Report</h1>
            <p class="metadata">Report generated: {report_data['metadata']['report_generated']}</p>
            <p>Files analyzed: {len(report_data['files_analyzed'])}</p>
            <p>OpenVINO Acceleration: {report_data['metadata']['analysis_context'].get('openvino_status', {}).get('available', False)}</p>
        </div>
""")

        # Summary section
        file_handle.write("""        <div class="section">
            <h2>Analysis Summary</h2>
""")
        
        # Include execution stats if available
        exec_stats = report_data['metadata']['analysis_context'].get('execution_stats', {})
        if exec_stats:
            file_handle.write(f"""            <p>Total modules executed: {exec_stats.get('completed_modules', 0)}/{exec_stats.get('total_modules', 0)}</p>
            <p>Files analyzed: {exec_stats.get('analyzed_files', 0)}</p>
            <p>Failed files: {exec_stats.get('failed_files', 0)}</p>
            <p>Total execution time: {report_data['metadata']['analysis_context'].get('total_execution_time', 0):.2f} seconds</p>
""")
        
        file_handle.write("        </div>\n")

        # File results section
        file_handle.write("""        <div class="section">
            <h2>File Analysis Results</h2>
""")
        
        for file_name, file_data in report_data['file_results'].items():
            metadata = file_data.get('metadata', {})
            components = file_data.get('components', {})
            
            file_handle.write(f"""            <div class="file-item">
                <h3>{file_name}</h3>
                <div class="metadata">
                    <p>Size: {metadata.get('file_size', 'Unknown')} bytes</p>
                    <p>MD5: {metadata.get('md5', 'Unknown')}</p>
                    <p>Analysis started: {metadata.get('analysis_started', 'Unknown')}</p>
                </div>
""")
            
            # Component results
            for comp_name, comp_results in components.items():
                status = comp_results.get('status', 'Unknown')
                findings = comp_results.get('findings', [])
                
                file_handle.write(f"""                <div class="component">
                    <h4>{comp_name}</h4>
                    <p>Status: {status}</p>
""")
                
                # Display findings if available
                if findings:
                    file_handle.write("                    <h5>Key Findings</h5>\n")
                    file_handle.write("                    <ul>\n")
                    
                    for finding in findings:
                        severity = finding.get('severity', 'low')
                        file_handle.write(f"                        <li class=\"finding {severity}\">{finding.get('description', '')}</li>\n")
                    
                    file_handle.write("                    </ul>\n")
                
                file_handle.write("                </div>\n")
            
            file_handle.write("            </div>\n")
        
        file_handle.write("        </div>\n")

        # Memory analysis section if available
        if 'memory_forensics' in report_data['global_results']:
            memory_results = report_data['global_results']['memory_forensics']
            meta = memory_results.get('metadata', {})
            results = memory_results.get('results', {})
            
            file_handle.write("""        <div class="section">
                <h2>Memory Forensics Analysis</h2>
""")
            
            file_handle.write(f"""            <div class="metadata">
                <p>Dump: {meta.get('dump_name', 'Unknown')}</p>
                <p>Size: {meta.get('dump_size', 'Unknown')} bytes</p>
                <p>Analysis started: {meta.get('analysis_started', 'Unknown')}</p>
            </div>
""")
            
            # Process memory analysis results
            for component, comp_results in results.items():
                file_handle.write(f"""            <div class="component">
                    <h3>{component}</h3>
""")
                
                # Processes
                processes = comp_results.get('processes', [])
                if processes:
                    file_handle.write(f"""                <h4>Processes ({len(processes)})</h4>
                    <table>
                        <tr>
                            <th>PID</th>
                            <th>Name</th>
                            <th>Score</th>
                            <th>Details</th>
                        </tr>
""")
                    
                    for proc in sorted(processes, key=lambda p: p.get('malicious_score', 0), reverse=True)[:10]:
                        file_handle.write(f"""                        <tr>
                            <td>{proc.get('pid', '?')}</td>
                            <td>{proc.get('name', 'Unknown')}</td>
                            <td>{proc.get('malicious_score', 0):.2f}</td>
                            <td>{proc.get('details', '')}</td>
                        </tr>
""")
                    
                    file_handle.write("                    </table>\n")
                
                # Artifacts
                artifacts = comp_results.get('artifacts', {})
                if artifacts:
                    file_handle.write("                <h4>Key Artifacts</h4>\n")
                    
                    for category, items in artifacts.items():
                        file_handle.write(f"                <h5>{category} ({len(items)})</h5>\n")
                        
                        if len(items) > 0:
                            file_handle.write("                <ul>\n")
                            for item in items[:5]:  # Show top 5
                                file_handle.write(f"                    <li>{item}</li>\n")
                            file_handle.write("                </ul>\n")
                            
                            if len(items) > 5:
                                file_handle.write(f"                <p>... and {len(items) - 5} more</p>\n")
                
                file_handle.write("            </div>\n")
            
            file_handle.write("        </div>\n")

        # Global analysis section
        file_handle.write("""        <div class="section">
            <h2>Global Analysis</h2>
""")
        
        # Cross-sample correlation if available
        if 'KeyplugCrossSampleCorrelator' in report_data['global_results']:
            correlator_results = report_data['global_results']['KeyplugCrossSampleCorrelator']
            
            file_handle.write("""            <div class="component">
                <h3>Cross-Sample Correlation</h3>
""")
            
            # Add specific correlation data visualization here
            
            file_handle.write("            </div>\n")
        
        # Pattern database if available
        if 'KeyplugPatternDatabase' in report_data['global_results']:
            pattern_db = report_data['global_results']['KeyplugPatternDatabase']
            
            file_handle.write("""            <div class="component">
                <h3>Pattern Database</h3>
""")
            
            # Add pattern database visualization here
            
            file_handle.write("            </div>\n")
        
        file_handle.write("        </div>\n")

        # Footer
        file_handle.write("""        <div class="footer">
            <p>KEYPLUG Analysis Framework - Report generated with ResultsProcessor v2.0.0</p>
        </div>
    </div>
</body>
</html>
""")

    def _write_summary_report(self, file_handle, report_data: Dict[str, Any]) -> None:
        """
        Write a concise summary report to the provided file handle.
        
        Args:
            file_handle: Open file handle to write to
            report_data: Complete report data dictionary
        """
        file_handle.write("KEYPLUG ANALYSIS SUMMARY REPORT\n")
        file_handle.write("==============================\n\n")
        
        # Metadata
        file_handle.write(f"Report Generated: {report_data['metadata']['report_generated']}\n")
        file_handle.write(f"Files Analyzed: {len(report_data['files_analyzed'])}\n")
        
        # Hardware acceleration status
        openvino_status = report_data['metadata']['analysis_context'].get('openvino_status', {})
        file_handle.write(f"OpenVINO Acceleration: {'Enabled - ' + openvino_status.get('preferred_device', 'Unknown') if openvino_status.get('available', False) else 'Disabled'}\n\n")
        
        # Execution statistics
        exec_stats = report_data['metadata']['analysis_context'].get('execution_stats', {})
        if exec_stats:
            file_handle.write(f"Execution Statistics:\n")
            file_handle.write(f"  Modules executed: {exec_stats.get('completed_modules', 0)}/{exec_stats.get('total_modules', 0)}\n")
            file_handle.write(f"  Files analyzed: {exec_stats.get('analyzed_files', 0)}\n")
            file_handle.write(f"  Failed files: {exec_stats.get('failed_files', 0)}\n")
            file_handle.write(f"  Total execution time: {report_data['metadata']['analysis_context'].get('total_execution_time', 0):.2f} seconds\n\n")
        
        # Summary of key findings across all files
        file_handle.write("KEY FINDINGS SUMMARY\n")
        file_handle.write("===================\n\n")
        
        total_high = 0
        total_medium = 0
        total_low = 0
        all_findings = []
        
        # Collect findings from all files
        for file_name, file_data in report_data['file_results'].items():
            components = file_data.get('components', {})
            
            for comp_name, comp_results in components.items():
                findings = comp_results.get('findings', [])
                
                for finding in findings:
                    severity = finding.get('severity', 'low')
                    if severity == 'high':
                        total_high += 1
                    elif severity == 'medium':
                        total_medium += 1
                    else:
                        total_low += 1
                    
                    all_findings.append({
                        'file': file_name,
                        'component': comp_name,
                        'severity': severity,
                        'description': finding.get('description', 'No description')
                    })
        
        # Write findings count
        file_handle.write(f"Total Findings: {len(all_findings)}\n")
        file_handle.write(f"  High severity: {total_high}\n")
        file_handle.write(f"  Medium severity: {total_medium}\n")
        file_handle.write(f"  Low severity: {total_low}\n\n")
        
        # List high severity findings
        if total_high > 0:
            file_handle.write("High Severity Findings:\n")
            file_handle.write("---------------------\n")
            
            high_findings = [f for f in all_findings if f['severity'] == 'high']
            for i, finding in enumerate(high_findings, 1):
                file_handle.write(f"{i}. [{finding['file']}] {finding['description']}\n")
            
            file_handle.write("\n")
        
        # List top 5 medium severity findings if any
        if total_medium > 0:
            file_handle.write("Medium Severity Findings (Top 5):\n")
            file_handle.write("-----------------------------\n")
            
            medium_findings = [f for f in all_findings if f['severity'] == 'medium'][:5]
            for i, finding in enumerate(medium_findings, 1):
                file_handle.write(f"{i}. [{finding['file']}] {finding['description']}\n")
            
            if total_medium > 5:
                file_handle.write(f"... and {total_medium - 5} more medium severity findings\n")
            
            file_handle.write("\n")
        
        # Memory analysis summary if available
        if 'memory_forensics' in report_data['global_results']:
            memory_results = report_data['global_results']['memory_forensics']
            results = memory_results.get('results', {})
            
            file_handle.write("MEMORY ANALYSIS SUMMARY\n")
            file_handle.write("======================\n\n")
            
            for component, comp_results in results.items():
                processes = comp_results.get('processes', [])
                suspicious_procs = [p for p in processes if p.get('malicious_score', 0) > 0.5]
                
                file_handle.write(f"{component}:\n")
                file_handle.write(f"  Total processes: {len(processes)}\n")
                file_handle.write(f"  Suspicious processes: {len(suspicious_procs)}\n")
                
                if suspicious_procs:
                    file_handle.write("  Top suspicious processes:\n")
                    sorted_procs = sorted(suspicious_procs, key=lambda p: p.get('malicious_score', 0), reverse=True)[:3]
                    
                    for proc in sorted_procs:
                        file_handle.write(f"    - {proc.get('name', 'Unknown')} (PID: {proc.get('pid', '?')}) - Score: {proc.get('malicious_score', 0):.2f}\n")
                
                file_handle.write("\n")
        
        # Recommendations section
        file_handle.write("RECOMMENDATIONS\n")
        file_handle.write("===============\n\n")
        
        if total_high > 0:
            file_handle.write("Critical Actions Required:\n")
            file_handle.write("  - Immediate isolation of affected systems\n")
            file_handle.write("  - Detailed forensic investigation\n")
            file_handle.write("  - Incident response procedures should be initiated\n\n")
        elif total_medium > 0:
            file_handle.write("Recommended Actions:\n")
            file_handle.write("  - Further investigation of suspicious indicators\n")
            file_handle.write("  - Monitoring of affected systems\n")
            file_handle.write("  - Review of security controls\n\n")
        else:
            file_handle.write("Recommended Actions:\n")
            file_handle.write("  - Continue monitoring systems\n")
            file_handle.write("  - Maintain regular security scans\n\n")

    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate MD5 hash of a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            MD5 hash as a hexadecimal string
        """
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()


if __name__ == "__main__":
    # Simple self-test
    processor = ResultsProcessor("./test_results")
    
    # Register a file
    test_file = __file__  # Use this script as a test file
    processor.register_file(test_file)
    
    # Store some results
    processor.store_file_result(
        os.path.basename(test_file),
        "TestComponent",
        {
            "status": "completed",
            "execution_time_seconds": 0.5,
            "findings": "This is a test result"
        }
    )
    
    # Generate a report
    report_paths = processor.generate_consolidated_report()
    
    print(f"Test completed. Reports generated at:")
    for fmt, path in report_paths.items():
        print(f"  {fmt}: {path}")
