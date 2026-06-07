//Ghidra Headless Script: DecompileFunction.java
//Decompiles functions and outputs C-like pseudocode to stdout
//
//Usage:
//  analyzeHeadless <project_dir> <project_name> -import <binary> \
//    -postScript DecompileFunction.java [function_name|address|"all"]
//
//Arguments:
//  - No args or "all": Decompile all functions
//  - Function name (e.g., "main"): Decompile specific function by name
//  - Address (e.g., "0x401000"): Decompile function at address
//
//@category BEAR
//@author BEAR Project

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class DecompileFunction extends GhidraScript {

    private DecompInterface decompiler;

    @Override
    public void run() throws Exception {
        // Initialize decompiler
        decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);

        String[] args = getScriptArgs();
        String target = (args != null && args.length > 0) ? args[0].trim() : "all";

        FunctionManager fm = currentProgram.getFunctionManager();

        // Start JSON output
        StringBuilder json = new StringBuilder();
        json.append("===BEAR_JSON_START===\n");
        json.append("{\n");
        json.append("  \"binary\": \"").append(escapeJson(currentProgram.getExecutablePath())).append("\",\n");
        json.append("  \"format\": \"").append(escapeJson(currentProgram.getExecutableFormat())).append("\",\n");
        json.append("  \"functions\": [\n");

        List<String> functionResults = new ArrayList<>();

        if (target.equalsIgnoreCase("all")) {
            // Decompile all functions
            FunctionIterator functions = fm.getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                Function func = functions.next();
                String result = decompileFunction(func);
                if (result != null) {
                    functionResults.add(result);
                }
            }
        } else if (target.startsWith("0x") || target.startsWith("0X") || isHexString(target)) {
            // Find by address
            Address addr = parseAddr(target);
            if (addr != null) {
                Function func = fm.getFunctionAt(addr);
                if (func == null) {
                    func = fm.getFunctionContaining(addr);
                }
                if (func != null) {
                    String result = decompileFunction(func);
                    if (result != null) {
                        functionResults.add(result);
                    }
                } else {
                    json.append("  ],\n");
                    json.append("  \"error\": \"Function not found at address: ").append(target).append("\"\n");
                    json.append("}\n");
                    json.append("===BEAR_JSON_END===");
                    println(json.toString());
                    decompiler.dispose();
                    return;
                }
            }
        } else {
            // Find by name
            Function func = findFunctionByName(target);
            if (func != null) {
                String result = decompileFunction(func);
                if (result != null) {
                    functionResults.add(result);
                }
            } else {
                json.append("  ],\n");
                json.append("  \"error\": \"Function not found: ").append(escapeJson(target)).append("\"\n");
                json.append("}\n");
                json.append("===BEAR_JSON_END===");
                println(json.toString());
                decompiler.dispose();
                return;
            }
        }

        // Join function results
        json.append(String.join(",\n", functionResults));
        json.append("\n  ]\n");
        json.append("}\n");
        json.append("===BEAR_JSON_END===");

        println(json.toString());
        decompiler.dispose();
    }

    private String decompileFunction(Function func) {
        if (func == null) return null;

        DecompileResults results = decompiler.decompileFunction(func, 60, monitor);

        StringBuilder sb = new StringBuilder();
        sb.append("    {\n");
        sb.append("      \"name\": \"").append(escapeJson(func.getName())).append("\",\n");
        sb.append("      \"address\": \"").append(func.getEntryPoint().toString()).append("\",\n");

        if (results == null || !results.decompileCompleted()) {
            sb.append("      \"error\": \"Decompilation failed or timed out\"\n");
            sb.append("    }");
            return sb.toString();
        }

        if (results.getDecompiledFunction() == null) {
            sb.append("      \"error\": \"No decompiled function available\"\n");
            sb.append("    }");
            return sb.toString();
        }

        String signature = results.getDecompiledFunction().getSignature();
        String code = results.getDecompiledFunction().getC();

        sb.append("      \"signature\": \"").append(escapeJson(signature != null ? signature : "")).append("\",\n");
        sb.append("      \"code\": \"").append(escapeJson(code != null ? code : "")).append("\"\n");
        sb.append("    }");

        return sb.toString();
    }

    private Function findFunctionByName(String name) {
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator functions = fm.getFunctions(true);
        while (functions.hasNext()) {
            Function func = functions.next();
            if (func.getName().equals(name)) {
                return func;
            }
        }
        return null;
    }

    private Address parseAddr(String addrStr) {
        try {
            if (addrStr.startsWith("0x") || addrStr.startsWith("0X")) {
                addrStr = addrStr.substring(2);
            }
            return currentProgram.getAddressFactory().getAddress(addrStr);
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isHexString(String s) {
        if (s == null || s.isEmpty()) return false;
        for (char c : s.toCharArray()) {
            if (!Character.isDigit(c) && "abcdefABCDEF".indexOf(c) == -1) {
                return false;
            }
        }
        return true;
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
