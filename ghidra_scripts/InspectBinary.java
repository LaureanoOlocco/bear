//Ghidra Headless Script: InspectBinary.java
//Provides functions, xrefs, and call graph inspection as JSON.
//
//Usage:
//  analyzeHeadless <project_dir> <project_name> -import <binary> \
//    -postScript InspectBinary.java functions
//    -postScript InspectBinary.java xrefs <target> <to|from|both> <auto|function|address|string|symbol>
//    -postScript InspectBinary.java callgraph <function|address|all> <out|in|both> <depth>
//
//@category BEAR
//@author BEAR Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class InspectBinary extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = (args != null && args.length > 0) ? args[0].trim().toLowerCase() : "functions";

        if (mode.equals("functions")) {
            emitFunctions();
        } else if (mode.equals("xrefs")) {
            String target = (args != null && args.length > 1) ? args[1].trim() : "";
            String direction = (args != null && args.length > 2) ? args[2].trim().toLowerCase() : "both";
            String targetType = (args != null && args.length > 3) ? args[3].trim().toLowerCase() : "auto";
            emitXrefs(target, direction, targetType);
        } else if (mode.equals("callgraph")) {
            String target = (args != null && args.length > 1) ? args[1].trim() : "all";
            String direction = (args != null && args.length > 2) ? args[2].trim().toLowerCase() : "out";
            int depth = (args != null && args.length > 3) ? parseInt(args[3], 2) : 2;
            emitCallgraph(target, direction, depth);
        } else {
            emitError("Unsupported inspection mode: " + escapeJson(mode));
        }
    }

    private void emitFunctions() {
        FunctionManager fm = currentProgram.getFunctionManager();
        FunctionIterator functions = fm.getFunctions(true);
        List<String> rows = new ArrayList<>();

        while (functions.hasNext() && !monitor.isCancelled()) {
            Function func = functions.next();
            StringBuilder row = new StringBuilder();
            row.append("    {\n");
            row.append("      \"name\": \"").append(escapeJson(func.getName())).append("\",\n");
            row.append("      \"address\": \"").append(func.getEntryPoint().toString()).append("\",\n");
            row.append("      \"namespace\": \"").append(escapeJson(func.getParentNamespace().getName(true))).append("\",\n");
            row.append("      \"signature\": \"").append(escapeJson(func.getSignature().toString())).append("\",\n");
            row.append("      \"size\": ").append(func.getBody().getNumAddresses()).append("\n");
            row.append("    }");
            rows.add(row.toString());
        }

        emitObject("\"functions\": [\n" + String.join(",\n", rows) + "\n  ]");
    }

    private void emitXrefs(String target, String direction, String targetType) {
        if (target == null || target.length() == 0) {
            emitError("target is required");
            return;
        }

        List<Address> addresses = resolveTargetAddresses(target, targetType);
        if (addresses.isEmpty()) {
            emitObject("\"target\": \"" + escapeJson(target) + "\",\n  \"target_type\": \"" + escapeJson(targetType) + "\",\n  \"xrefs_to\": [],\n  \"xrefs_from\": [],\n  \"error\": \"Target not found\"");
            return;
        }

        List<String> xrefsTo = new ArrayList<>();
        List<String> xrefsFrom = new ArrayList<>();
        ReferenceManager rm = currentProgram.getReferenceManager();

        for (Address addr : addresses) {
            if (direction.equals("to") || direction.equals("both")) {
                ReferenceIterator refsTo = rm.getReferencesTo(addr);
                while (refsTo.hasNext() && !monitor.isCancelled()) {
                    xrefsTo.add(formatReference(refsTo.next(), true));
                }
            }

            if (direction.equals("from") || direction.equals("both")) {
                Function func = currentProgram.getFunctionManager().getFunctionContaining(addr);
                if (func != null) {
                    for (Address from : func.getBody().getAddresses(true)) {
                        Reference[] refs = rm.getReferencesFrom(from);
                        for (Reference ref : refs) {
                            xrefsFrom.add(formatReference(ref, false));
                        }
                    }
                } else {
                    Reference[] refs = rm.getReferencesFrom(addr);
                    for (Reference ref : refs) {
                        xrefsFrom.add(formatReference(ref, false));
                    }
                }
            }
        }

        StringBuilder body = new StringBuilder();
        body.append("\"target\": \"").append(escapeJson(target)).append("\",\n");
        body.append("  \"target_type\": \"").append(escapeJson(targetType)).append("\",\n");
        body.append("  \"resolved_addresses\": [").append(formatAddressArray(addresses)).append("],\n");
        body.append("  \"xrefs_to\": [\n").append(String.join(",\n", xrefsTo)).append("\n  ],\n");
        body.append("  \"xrefs_from\": [\n").append(String.join(",\n", xrefsFrom)).append("\n  ]");
        emitObject(body.toString());
    }

    private void emitCallgraph(String target, String direction, int depth) throws Exception {
        List<Function> roots = resolveFunctions(target);
        Map<String, Set<String>> graph = new LinkedHashMap<>();

        for (Function root : roots) {
            walkCallgraph(root, direction, depth, graph, new LinkedHashSet<String>());
        }

        List<String> entries = new ArrayList<>();
        for (Map.Entry<String, Set<String>> entry : graph.entrySet()) {
            List<String> callees = new ArrayList<>();
            for (String name : entry.getValue()) {
                callees.add("\"" + escapeJson(name) + "\"");
            }
            entries.add("    \"" + escapeJson(entry.getKey()) + "\": [" + String.join(", ", callees) + "]");
        }

        StringBuilder body = new StringBuilder();
        body.append("\"function\": \"").append(escapeJson(target)).append("\",\n");
        body.append("  \"direction\": \"").append(escapeJson(direction)).append("\",\n");
        body.append("  \"depth\": ").append(depth).append(",\n");
        body.append("  \"callgraph\": {\n").append(String.join(",\n", entries)).append("\n  }");
        emitObject(body.toString());
    }

    private void walkCallgraph(Function func, String direction, int depth, Map<String, Set<String>> graph, Set<String> seen) throws Exception {
        if (func == null || depth < 0 || monitor.isCancelled()) return;

        String key = func.getName();
        if (!graph.containsKey(key)) {
            graph.put(key, new LinkedHashSet<String>());
        }
        if (seen.contains(key) || depth == 0) return;
        seen.add(key);

        Set<Function> related = new LinkedHashSet<Function>();
        if (direction.equals("out") || direction.equals("both")) {
            related.addAll(func.getCalledFunctions(monitor));
        }
        if (direction.equals("in") || direction.equals("both")) {
            related.addAll(func.getCallingFunctions(monitor));
        }

        for (Function next : related) {
            graph.get(key).add(next.getName());
            walkCallgraph(next, direction, depth - 1, graph, new LinkedHashSet<String>(seen));
        }
    }

    private String formatReference(Reference ref, boolean toReference) {
        Function fromFunc = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        Function toFunc = currentProgram.getFunctionManager().getFunctionContaining(ref.getToAddress());
        StringBuilder row = new StringBuilder();
        row.append("    {");
        row.append("\"from_address\": \"").append(ref.getFromAddress().toString()).append("\", ");
        row.append("\"to_address\": \"").append(ref.getToAddress().toString()).append("\", ");
        row.append("\"from_function\": \"").append(escapeJson(fromFunc != null ? fromFunc.getName() : "")).append("\", ");
        row.append("\"to_function\": \"").append(escapeJson(toFunc != null ? toFunc.getName() : "")).append("\", ");
        row.append("\"reference_type\": \"").append(escapeJson(ref.getReferenceType().toString())).append("\"");
        row.append("}");
        return row.toString();
    }

    private List<Address> resolveTargetAddresses(String target, String targetType) {
        List<Address> addresses = new ArrayList<>();

        if (targetType.equals("auto") || targetType.equals("address")) {
            Address addr = parseAddr(target);
            if (addr != null) addresses.add(addr);
        }

        if (targetType.equals("auto") || targetType.equals("function")) {
            Function func = findFunctionByName(target);
            if (func != null) addresses.add(func.getEntryPoint());
        }

        if (targetType.equals("auto") || targetType.equals("symbol")) {
            SymbolTable st = currentProgram.getSymbolTable();
            SymbolIterator symbols = st.getSymbols(target);
            while (symbols.hasNext()) {
                addresses.add(symbols.next().getAddress());
            }
        }

        if (targetType.equals("auto") || targetType.equals("string")) {
            Listing listing = currentProgram.getListing();
            DataIterator data = listing.getDefinedData(true);
            while (data.hasNext() && !monitor.isCancelled()) {
                Data d = data.next();
                Object value = d.getValue();
                if (value != null && value.toString().contains(target)) {
                    addresses.add(d.getAddress());
                }
            }
        }

        return addresses;
    }

    private List<Function> resolveFunctions(String target) {
        List<Function> functions = new ArrayList<>();
        FunctionManager fm = currentProgram.getFunctionManager();

        if (target == null || target.length() == 0 || target.equalsIgnoreCase("all")) {
            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext() && !monitor.isCancelled()) {
                functions.add(iter.next());
            }
            return functions;
        }

        Address addr = parseAddr(target);
        if (addr != null) {
            Function func = fm.getFunctionAt(addr);
            if (func == null) func = fm.getFunctionContaining(addr);
            if (func != null) functions.add(func);
        }

        Function byName = findFunctionByName(target);
        if (byName != null && !functions.contains(byName)) {
            functions.add(byName);
        }

        return functions;
    }

    private Function findFunctionByName(String name) {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function func = functions.next();
            if (func.getName().equals(name)) {
                return func;
            }
        }
        return null;
    }

    private String formatAddressArray(List<Address> addresses) {
        List<String> rows = new ArrayList<>();
        for (Address addr : addresses) {
            rows.add("\"" + addr.toString() + "\"");
        }
        return String.join(", ", rows);
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

    private int parseInt(String value, int defaultValue) {
        try {
            return Integer.parseInt(value);
        } catch (Exception e) {
            return defaultValue;
        }
    }

    private void emitObject(String body) {
        StringBuilder json = new StringBuilder();
        json.append("===BEAR_JSON_START===\n");
        json.append("{\n");
        json.append("  \"binary\": \"").append(escapeJson(currentProgram.getExecutablePath())).append("\",\n");
        json.append("  \"format\": \"").append(escapeJson(currentProgram.getExecutableFormat())).append("\",\n");
        json.append("  ").append(body).append("\n");
        json.append("}\n");
        json.append("===BEAR_JSON_END===");
        println(json.toString());
    }

    private void emitError(String message) {
        emitObject("\"error\": \"" + message + "\"");
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
