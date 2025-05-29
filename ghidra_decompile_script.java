import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Map; // For signature data
import java.util.LinkedHashMap; // For preserving order in JSON objects

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Parameter; // For function parameters
import ghidra.program.model.symbol.SourceType; // For parameter names if available
import ghidra.program.model.address.Address;
import ghidra.program.model.block.*; // For CFG CodeBlockModel, CodeBlock, CodeBlockReference
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.util.task.TaskMonitor;
import ghidra.util.NumericUtilities; // For hex string formatting

public class DecompileScript extends GhidraScript {

    // Helper to escape strings for JSON
    private String escapeJson(String str) {
        if (str == null) return "null"; // Use JSON null for null strings
        // Basic escaping for quotes, backslashes, and control characters
        return "\\\"" + str.replace("\\\\", "\\\\\\\\").replace("\\\"", "\\\\\\\"").replace("\\b", "\\\\b")
                          .replace("\\f", "\\\\f").replace("\\n", "\\\\n").replace("\\r", "\\\\r")
                          .replace("\\t", "\\\\t") + "\\\"";
    }

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        FunctionManager functionManager = program.getFunctionManager();
        DecompInterface decompInterface = new DecompInterface();
        
        // Initialize decompiler
        decompInterface.openProgram(program);
        
        // Create output directory if it doesn't exist
        File outputDirFile = new File("%s"); 
        if (!outputDirFile.exists()) {
            outputDirFile.mkdirs();
        }
        
        // C code output file
        File cOutputFile = new File(outputDirFile, "%s");
        FileWriter cWriter = new FileWriter(cOutputFile);
        
        // JSON signatures output file
        File jsonOutputFile = new File(outputDirFile, "%s");
        FileWriter jsonWriter = new FileWriter(jsonOutputFile);

        // CFG DOT output file
        File cfgOutputFile = new File(outputDirFile, "%s");
        FileWriter cfgWriter = new FileWriter(cfgOutputFile);
        
        // Write C header
        cWriter.write("// Decompiled with Ghidra\\n");
        cWriter.write("// Binary: " + program.getName() + "\\n");
        cWriter.write("// Timestamp: " + new java.util.Date() + "\\n\\n");
        
        List<Map<String, Object>> allFunctionsData = new ArrayList<>();

        // Get functions to decompile
        List<Function> functionsToDecompile = new ArrayList<>();
        %s
        
        // Decompile functions and collect data
        int totalFunctions = functionsToDecompile.size();
        int processedFunctions = 0;
        
        for (Function function : functionsToDecompile) {
            processedFunctions++;
            // Use monitor from GhidraScript base class
            monitor.setMessage("Processing function " + processedFunctions + "/" + totalFunctions + ": " + function.getName());
            if (monitor.isCancelled()) break;

            Map<String, Object> funcData = new LinkedHashMap<>();
            funcData.put("name", function.getName());
            funcData.put("address", function.getEntryPoint().toString());
            funcData.put("return_type", function.getReturnType().getName());

            List<Map<String, String>> paramsList = new ArrayList<>();
            Parameter[] params = function.getParameters();
            for (Parameter param : params) {
                Map<String, String> paramData = new LinkedHashMap<>();
                String paramName = param.getName();
                paramData.put("name", paramName);
                paramData.put("type", param.getDataType().getName());
                paramsList.add(paramData);
            }
            funcData.put("parameters", paramsList);
            
            DecompileResults results = decompInterface.decompileFunction(function, 120, monitor);
            if (results.decompileCompleted()) {
                String decompiledC = results.getDecompiledFunction().getC();
                cWriter.write("// Function: " + function.getName() + "\\n");
                cWriter.write("// Address: " + function.getEntryPoint() + "\\n\\n");
                cWriter.write(decompiledC);
                cWriter.write("\\n\\n");
            } else {
                cWriter.write("// Failed to decompile function: " + function.getName() + "\\n\\n");
            }
            allFunctionsData.add(funcData);

            try {
                cfgWriter.write("digraph \\"" + escapeJsonString(function.getName()) + "_cfg\\" {\\n");
                cfgWriter.write("  label=\\"" + escapeJsonString(function.getName() + " CFG") + "\\";\\n");
                
                CodeBlockModel blockModel = new BasicBlockModel(program);
                CodeBlock[] blocks = blockModel.getCodeBlocksContaining(function.getBody(), monitor);
                
                for (CodeBlock block : blocks) {
                    String blockName = block.getName();
                    String entryPoint = block.getFirstStartAddress().toString();
                    cfgWriter.write("  \\"" + entryPoint + "\\" [label=\\"" + escapeJsonString(blockName) + "\\n" + escapeJsonString(entryPoint) + "\\"];\\n");
                    
                    CodeBlockReference[] dests = block.getDestinations(monitor);
                    for (CodeBlockReference destRef : dests) {
                        Address destAddr = destRef.getDestinationAddress();
                        cfgWriter.write("  \\"" + entryPoint + "\\" -> \\"" + destAddr.toString() + "\\";\\n");
                    }
                }
                cfgWriter.write("}\\n\\n"); 
            } catch (Exception cfgEx) {
                println("Error exporting CFG for " + function.getName() + ": " + cfgEx.getMessage());
                cfgWriter.write("// Error exporting CFG for " + function.getName() + ": " + cfgEx.getMessage() + "\\n");
            }
        }
        
        cWriter.close();
        cfgWriter.close(); 
        println("C Decompilation complete. Output saved to: " + cOutputFile.getAbsolutePath());
        println("CFG DOT export complete. Output saved to: " + cfgOutputFile.getAbsolutePath());

        jsonWriter.write("[\\n");
        for (int i = 0; i < allFunctionsData.size(); i++) {
            Map<String, Object> funcData = allFunctionsData.get(i);
            jsonWriter.write("  {\\n");
            jsonWriter.write("    " + escapeJson("name") + ": " + escapeJson((String) funcData.get("name")) + ",\\n");
            jsonWriter.write("    " + escapeJson("address") + ": " + escapeJson((String) funcData.get("address")) + ",\\n");
            jsonWriter.write("    " + escapeJson("return_type") + ": " + escapeJson((String) funcData.get("return_type")) + ",\\n");
            
            jsonWriter.write("    " + escapeJson("parameters") + ": [\\n");
            @SuppressWarnings("unchecked") 
            List<Map<String, String>> paramsList = (List<Map<String, String>>) funcData.get("parameters");
            for (int j = 0; j < paramsList.size(); j++) {
                Map<String, String> paramData = paramsList.get(j);
                jsonWriter.write("      {\\n");
                jsonWriter.write("        " + escapeJson("name") + ": " + escapeJson(paramData.get("name")) + ",\\n");
                jsonWriter.write("        " + escapeJson("type") + ": " + escapeJson(paramData.get("type")) + "\\n");
                jsonWriter.write("      }" + (j < paramsList.size() - 1 ? "," : "") + "\\n");
            }
            jsonWriter.write("    ]\\n");
            jsonWriter.write("  }" + (i < allFunctionsData.size() - 1 ? "," : "") + "\\n");
        }
        jsonWriter.write("]\\n");
        jsonWriter.close();
        println("JSON Signatures complete. Output saved to: " + jsonOutputFile.getAbsolutePath());
    }

    private String escapeJsonString(String str) { 
        if (str == null) return "";
        return str.replace("\\\\", "\\\\\\\\").replace("\\\"", "\\\\\\\"").replace("\\n", "\\\\n");
    }
}
