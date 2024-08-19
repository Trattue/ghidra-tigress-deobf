import java.io.File;
import java.util.ArrayList;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.app.util.Option;
import ghidra.app.util.exporter.CppExporter;
import ghidra.app.util.headless.HeadlessScript;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.SourceType;

public class Export extends HeadlessScript {
	@Override
	protected void run() throws Exception {
		// Auto create locals struct
		var decOpts = DecompilerUtils.getDecompileOptions(state.getTool(), currentProgram);
		var ifc = new DecompInterface();
		ifc.setOptions(decOpts);
		ifc.openProgram(currentProgram);
		var fosh = new FillOutStructureHelper(currentProgram, decOpts, monitor);
		var funcs = currentProgram.getFunctionManager().getFunctions(true);
		for (var f : funcs) {
			var res = ifc.decompileFunction(f, 60, monitor);
			var syms = res.getHighFunction().getLocalSymbolMap().getNameToSymbolMap();
			for (String s : syms.keySet()) {
				println(f.getName() + " " + s);
				if (s.startsWith("in_locals")) {
					var sym = syms.get(s);
					var struct = fosh.processStructure(sym.getHighVariable(), f, false, true);
					var dt = new PointerDataType(struct);
					currentProgram.getDataTypeManager().addDataType(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
					HighFunctionDBUtil.updateDBVariable(sym, null, dt, SourceType.USER_DEFINED);
				}
			}

			// Set calling convention for VM function
			f.setCallingConvention("vm");
			
			// Get return value size of called functions
			var ops = res.getHighFunction().getPcodeOps();
			while (ops.hasNext()) {
				var op = ops.next();
				if(op.getMnemonic().equals("CALL")) {
					print("CALL");
					for (var i : op.getInputs()) {
						if(i.getAddress().getAddressSpace().getName().equalsIgnoreCase("ram")) {
							print(" 0x" + Long.toHexString(i.getOffset()));
							break;
						}
					}
					print(" retsize: " + op.getOutput().getSize() + "\n");
				}
			}
		}

		// Export pseudocode
		var file = new File("samples/" + currentProgram.getName() + ".dec");
		file.createNewFile();
		var exp = new CppExporter();
		var options = new ArrayList<Option>();
		options.add(new Option(CppExporter.CREATE_HEADER_FILE, false));
		exp.setOptions(options);
		exp.setExporterServiceProvider(state.getTool());
		exp.export(file, currentProgram, null, monitor);
		println("Exported program to " + file.getAbsolutePath());
	}
}
