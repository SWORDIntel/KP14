"""JSON Export Module - Convert analysis results to JSON formats"""

import json
from typing import Dict, Any, List, IO
from pathlib import Path
from datetime import datetime


class JSONExporter:
    """Export analysis results as JSON"""

    def __init__(self, pretty: bool = False, indent: int = 2):
        """
        Initialize JSON exporter

        Args:
            pretty: Enable pretty printing
            indent: Indentation spaces (if pretty=True)
        """
        self.pretty = pretty
        self.indent = indent if pretty else None

    def export(self, results: Dict[str, Any], output_path: str = None) -> str:
        """
        Export results as JSON

        Args:
            results: Analysis results dictionary
            output_path: Optional file path to write

        Returns:
            JSON string
        """
        # Add export metadata
        export_data = {
            "export_metadata": {
                "format": "kp14-json",
                "version": "1.0",
                "exported_at": datetime.utcnow().isoformat() + "Z"
            },
            **results
        }

        # Serialize to JSON
        json_str = json.dumps(
            export_data,
            indent=self.indent,
            default=self._json_encoder,
            separators=(',', ': ') if self.pretty else (',', ':')
        )

        # Write to file if path provided
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(json_str)

        return json_str

    def export_batch(self, results_list: List[Dict[str, Any]], output_path: str) -> None:
        """
        Export multiple results as JSON array

        Args:
            results_list: List of analysis results
            output_path: File path to write
        """
        batch_data = {
            "export_metadata": {
                "format": "kp14-json-batch",
                "version": "1.0",
                "exported_at": datetime.utcnow().isoformat() + "Z",
                "total_results": len(results_list)
            },
            "results": results_list
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump(batch_data, f, indent=self.indent, default=self._json_encoder)

    def _json_encoder(self, obj):
        """Custom JSON encoder for non-serializable types"""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, set):
            return list(obj)
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        raise TypeError(f"Object of type {type(obj)} not JSON serializable")


class JSONLExporter:
    """Export analysis results as JSON Lines (streaming format)"""

    def __init__(self):
        """Initialize JSONL exporter"""
        pass

    def export(self, result: Dict[str, Any], file_handle: IO) -> None:
        """
        Append single result to JSONL file

        Args:
            result: Analysis result dictionary
            file_handle: Open file handle for writing
        """
        json_line = json.dumps(result, default=self._json_encoder)
        file_handle.write(json_line + '\n')
        file_handle.flush()

    def export_batch(self, results_list: List[Dict[str, Any]], output_path: str) -> None:
        """
        Export multiple results as JSONL

        Args:
            results_list: List of analysis results
            output_path: File path to write
        """
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            for result in results_list:
                self.export(result, f)

    def read(self, input_path: str) -> List[Dict[str, Any]]:
        """
        Read JSONL file and return results list

        Args:
            input_path: Path to JSONL file

        Returns:
            List of result dictionaries
        """
        results = []
        with open(input_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(json.loads(line))
        return results

    def _json_encoder(self, obj):
        """Custom JSON encoder"""
        if isinstance(obj, bytes):
            return obj.hex()
        elif isinstance(obj, Path):
            return str(obj)
        elif isinstance(obj, set):
            return list(obj)
        raise TypeError(f"Object of type {type(obj)} not JSON serializable")
