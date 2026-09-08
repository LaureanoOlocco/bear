//Ghidra Headless Script: DisassembleFunction.java
//Disassembles functions and outputs JSON to stdout
//
//Usage:
//  analyzeHeadless <project_dir> <project_name> -import <binary> \
//    -postScript DisassembleFunction.java [function_name|address|"all"]
//
//@category BEAR
//@author BEAR Project

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.util.NumericUtilities;

import java.util.ArrayList;
import java.util.List;

public class DisassembleFunction extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String target = (args != null && args.length > 0) ? args[0].trim() : "all";

        FunctionManager fm = currentProgram.getFunctionManager();
        List<String> functionResults = new ArrayList<>();

        if (target.equalsIgnoreCase("all")) {
            FunctionIterator functions = fm.getFunctions(true);
            while (functions.hasNext() && !monitor.isCancelled()) {
                functionResults.add(disassembleFunction(functions.next()));
            }
        } else if (target.startsWith("0x") || target.startsWith("0X") || isHexString(target)) {
            Address addr = parseAddr(target);
            Function func = null;
            if (addr != null) {
                func = fm.getFunctionAt(addr);
                if (func == null) {
                    func = fm.getFunctionContaining(addr);
                }
            }
            if (func == null) {
                emitError("Function not found at address: " + escapeJson(target));
                return;
            }
            functionResults.add(disassembleFunction(func));
        } else {
            Function func = findFunctionByName(target);
            if (func == null) {
                emitError("Function not found: " + escapeJson(target));
                return;
            }
            functionResults.add(disassembleFunction(func));
        }

        StringBuilder json = new StringBuilder();
        json.append("===BEAR_JSON_START===\n");
        json.append("{\n");
        json.append("  \"binary\": \"").append(escapeJson(currentProgram.getExecutablePath())).append("\",\n");
        json.append("  \"format\": \"").append(escapeJson(currentProgram.getExecutableFormat())).append("\",\n");
        json.append("  \"functions\": [\n");
        json.append(String.join(",\n", functionResults));
        json.append("\n  ]\n");
        json.append("}\n");
        json.append("===BEAR_JSON_END===");

        println(json.toString());
    }

    private String disassembleFunction(Function func) throws Exception {
        Listing listing = currentProgram.getListing();
        InstructionIterator instructions = listing.getInstructions(func.getBody(), true);
        List<String> rows = new ArrayList<>();

        while (instructions.hasNext() && !monitor.isCancelled()) {
            Instruction instr = instructions.next();
            StringBuilder row = new StringBuilder();
            row.append("        {");
            row.append("\"address\": \"").append(instr.getAddress().toString()).append("\", ");
            row.append("\"mnemonic\": \"").append(escapeJson(instr.getMnemonicString())).append("\", ");
            row.append("\"operands\": \"").append(escapeJson(formatOperands(instr))).append("\", ");
            row.append("\"bytes\": \"").append(NumericUtilities.convertBytesToString(instr.getBytes())).append("\"");
            row.append("}");
            rows.add(row.toString());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("    {\n");
        sb.append("      \"name\": \"").append(escapeJson(func.getName())).append("\",\n");
        sb.append("      \"address\": \"").append(func.getEntryPoint().toString()).append("\",\n");
        sb.append("      \"instructions\": [\n");
        sb.append(String.join(",\n", rows));
        sb.append("\n      ]\n");
        sb.append("    }");
        return sb.toString();
    }

    private String formatOperands(Instruction instr) {
        List<String> operands = new ArrayList<>();
        for (int i = 0; i < instr.getNumOperands(); i++) {
            operands.add(instr.getDefaultOperandRepresentation(i));
        }
        return String.join(", ", operands);
    }

    private void emitError(String message) {
        StringBuilder json = new StringBuilder();
        json.append("===BEAR_JSON_START===\n");
        json.append("{\n");
        json.append("  \"binary\": \"").append(escapeJson(currentProgram.getExecutablePath())).append("\",\n");
        json.append("  \"format\": \"").append(escapeJson(currentProgram.getExecutableFormat())).append("\",\n");
        json.append("  \"functions\": [],\n");
        json.append("  \"error\": \"").append(message).append("\"\n");
        json.append("}\n");
        json.append("===BEAR_JSON_END===");
        println(json.toString());
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
