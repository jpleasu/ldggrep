// based on Ghidra's AskDialog
package com.github.jpleasu.ldggrep.ghidra.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.*;
import java.net.URL;
import java.util.List;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import javax.swing.event.HyperlinkListener;
import javax.swing.text.*;
import javax.swing.text.html.HTMLEditorKit;
import javax.swing.text.html.StyleSheet;

import org.apache.commons.text.StringEscapeUtils;

import com.github.jpleasu.ldggrep.ghidra.BaseGhidraGrep;
import com.github.jpleasu.ldggrep.ghidra.util.Util;
import com.github.jpleasu.ldggrep.*;
import com.github.jpleasu.ldggrep.MethodManager.PredEnumerator;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import generic.jar.ResourceFile;
import generic.timer.GhidraSwingTimer;
import generic.util.Path;
import ghidra.framework.Application;
import ghidra.util.SystemUtilities;
import utilities.util.FileUtilities;

public class LDGGrepDialog<N, E> extends DialogComponentProvider {
	public static final String HELPFILENAME = "LDGGrepHelp.html";
	private boolean isCanceled;
	private JComboBox<String> comboField;
	final LDGGrepHistory qh;
	final LDGModel<N, E> model;
	public boolean show_stomem = false;
	public boolean show_graph = true;
	private BaseGhidraGrep<N, E> script;
	final String name;

	private ResourceFile getHelpFile() {
		ResourceFile helpFile;
		try {
			helpFile = Application.getModuleDataFile("LDGGrep", HELPFILENAME);
		}
		catch (FileNotFoundException e0) {
			URL url = LDGMatcher.class.getProtectionDomain().getCodeSource().getLocation();
			try {
				// reset cache entry in ResourceFile#jarRootsMap
				ResourceFile.openJarResourceFile(new File(url.getFile()), null);
				helpFile = new ResourceFile("jar:" + url.toString() + "!/data/" + HELPFILENAME);
				if (!helpFile.exists()) {
					throw new RuntimeException(
						"Can't find LDGGrep help file in Module or resources");
				}
			}
			catch (IOException e1) {
				throw new RuntimeException("Can't open LDGGrep jar for help file", e1);
			}
		}
		return helpFile;
	}

	public LDGGrepDialog(BaseGhidraGrep<N, E> script, LDGModel<N, E> model, LDGGrepHistory qh) {
		super(script.getClass().getSimpleName(), true, true, true, false);
		this.name = script.getClass().getSimpleName();
		this.script = script;
		this.model = model;
		String message = "Enter a query expression for " + name + ":";
		this.qh = qh;

		List<String> choices = qh.asList();

		JPanel query_panel = new JPanel(new BorderLayout(10, 10));
		query_panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		query_panel.add(new JLabel(message), BorderLayout.WEST);

		comboField = new JComboBox<>(choices.toArray(new String[choices.size()]));
		comboField.setEditable(true);
		comboField.setName("JComboBox");
		if (choices.size() > 0) {
			comboField.insertItemAt("- clear history -", choices.size());
			comboField.setSelectedIndex(0);
			comboField.getEditor().selectAll();

			comboField.addActionListener(ev -> {
				if (comboField.getSelectedIndex() == choices.size() &&
					ev.getActionCommand().equals("comboBoxEdited")) {
					comboField.removeAllItems();
					qh.clear();
					setStatusText("History cleared.");
					new GhidraSwingTimer(1000, () -> {
						setStatusText("");
					}).start();
				}
			});
		}

		query_panel.add(comboField, BorderLayout.CENTER);

		JEditorPane jep = new JEditorPane();
		jep.setEditable(false);
		JScrollPane help_panel = new JScrollPane(jep);
		HTMLEditorKit k = new HTMLEditorKit();
		jep.setEditorKit(k);

		StyleSheet ss = k.getStyleSheet();
		ss.addRule("body {font-size:14pt}");
		ss.addRule(".code {font-family:monospace;background-color:#f0f0f0}");

		final Document doc = k.createDefaultDocument();
		jep.setDocument(doc);

		jep.setText(buildHelpHtml());

		jep.setPreferredSize(new Dimension(800, 400));

		jep.addHyperlinkListener(new HyperlinkListener() {
			@Override
			public void hyperlinkUpdate(HyperlinkEvent e) {
				if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED) {
					Element el = e.getSourceElement();
					try {
						if ("#".equals(e.getDescription())) {
							int p0 = el.getStartOffset();
							int p1 = el.getEndOffset();
							String q = doc.getText(p0, p1 - p0);
							comboField.setSelectedItem(q);
						}
						else {
							Util.browseExternalLink(e);
						}
					}
					catch (BadLocationException e1) {
						e1.printStackTrace();
					}
				}
			}
		});

		addWorkPanel(new JSplitPane(JSplitPane.VERTICAL_SPLIT, query_panel, help_panel));

		JButton butt;
		butt = new JButton("mem");
		butt.setMnemonic('M');
		butt.setName("mem");
		butt.addActionListener(e -> {
			show_stomem = true;
			show_graph = false;
			okCallback();
		});
		addButton(butt);

		butt = new JButton("mem+graph");
		butt.setMnemonic('+');
		butt.setName("mem+graph");
		butt.addActionListener(e -> {
			show_stomem = true;
			show_graph = true;
			okCallback();
		});
		addButton(butt);

		addOKButton();
		setDefaultButton(okButton);
		okButton.setMnemonic('G');
		okButton.setText("graph");

		addCancelButton();

		setRememberSize(true);
		SystemUtilities
				.runSwingNow(() -> DockingWindowManager.showDialog(null, LDGGrepDialog.this));
	}

	private String buildHelpHtml() {
		StringBuilder html = new StringBuilder();

		ResourceFile helpFile = getHelpFile();

		ResourceFile examplesFile =
			new ResourceFile(script.getSourceFile().getParentFile(), name + "Examples.txt");

		String examplesFilePath = Path.toPathString(examplesFile);

		html.append("<h1>Examples</h1>\n");
		if (examplesFile.exists()) {
			html.append("from " + examplesFilePath + "\n<br/><br/>\n");

			html.append("<pre>\n");
			try (BufferedReader reader =
				new BufferedReader(new InputStreamReader(examplesFile.getInputStream()))) {
				while (reader.ready()) {
					String line = reader.readLine();
					if (line.startsWith(":  "))
						html.append(String.format("  <a class=\"code\" href=\"#\">%s</a>\n",
							StringEscapeUtils.escapeHtml4(line.substring(3).trim())));
					else
						html.append(line).append('\n');
				}
			}
			catch (IOException e) {
				throw new RuntimeException("Can't read LDGGrep exmaples file " + examplesFile, e);
			}
			html.append("</pre>\n");
		}
		else {
			html.append("No examples file found at " + examplesFilePath + "\n<br/><br/>\n");
		}

		// add predicates
		PredEnumerator enumerator = (proto, desc) -> {
			html.append(StringEscapeUtils
					.escapeHtml4("  " + proto + (!desc.isEmpty() ? " - " + desc : "") + "\n"));
		};

		MethodManager methodManager = model.getMethodManager();

		html.append("<h1>Node predicates</h1>\n");
		html.append("<pre>\n");
		methodManager.forEachPred(NPred.class, enumerator);
		html.append("</pre>\n");

		html.append("<h1>Edge predicates</h1>\n");
		html.append("<pre>\n");
		methodManager.forEachPred(EPred.class, enumerator);
		html.append("</pre>\n");

		// append helpfile to the bottom
		try (InputStream is = helpFile.getInputStream()) {
			html.append(FileUtilities.getText(is));
		}
		catch (IOException e) {
			throw new RuntimeException("Can't read LDGGrep helpfile", e);
		}
		html.append(
			"<br/><br/><b>Visit <a href=\"https://github.com/jpleasu/ldggrep\">LDGGrep on GitHub</a> for more help.</b>\n");

		return html.toString();
	}

	String expr_string = null;

	@Override
	protected void okCallback() {
		isCanceled = false;
		expr_string = (String) comboField.getSelectedItem();

		if (expr_string == null || expr_string.trim().isEmpty()) {
			setStatusText("Please make a selection, or enter a new query");
		}
		else {
			expr_string = expr_string.trim();
			qh.add(expr_string);
			close();
		}
	}

	@Override
	protected void cancelCallback() {
		isCanceled = true;
		close();
	}

	public boolean isCanceled() {
		return isCanceled;
	}

	public String getValueAsString() {
		return expr_string;
	}

}
