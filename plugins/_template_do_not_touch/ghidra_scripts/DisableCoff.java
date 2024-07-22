import ghidra.app.util.headless.HeadlessScript;
import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

public class DisableCoff extends HeadlessScript {
	@Override
	protected void run() throws Exception {
		Options opts = currentProgram.getOptions(Program.ANALYSIS_PROPERTIES);
		opts.setBoolean("COFF Header Annotation", false);
	}
}
