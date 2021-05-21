//RefGrep, but include data nodes at start
//@category LDGGrep
//@keybinding ctrl 5

import java.util.stream.Stream;
import java.util.stream.StreamSupport;

import com.github.jpleasu.ldggrep.LDG;
import com.github.jpleasu.ldggrep.ghidra.*;

import ghidra.program.model.address.Address;

public class RefGrepWithDataStarts extends RefGrep {
	@Override
	protected LDG<Address, RefEdge> newLDG() {
		return new ReferenceGrepGraph(currentProgram) {
			@Override
			public Stream<Address> startNodes() {
				return Stream.concat(super.startNodes(),
					StreamSupport.stream(currentProgram.getReferenceManager()
							.getReferenceSourceIterator(currentProgram.getMinAddress(), true)
							.spliterator(),
						true));
			}
		};
	}
}
