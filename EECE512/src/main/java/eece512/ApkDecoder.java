package eece512;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

import polyglot.main.Main;
import soot.Body;
import soot.BodyTransformer;
import soot.G;
import soot.PackManager;
import soot.SootMethod;
import soot.Transform;
import soot.Unit;
import soot.Value;
import soot.ValueBox;
import soot.jimple.*;
import soot.options.Options;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.ForwardFlowAnalysis;

public class ApkDecoder {
	public static void apkTool(String apkPath) throws Exception {
		System.out.println("Decoding APK " + apkPath);

		// Check files exist
		if (!new File(apkPath).exists()) {
			throw new Exception("APK " + apkPath + "not exists");
		}

		// Run ApkTool
		brut.androlib.ApkDecoder decoder = new brut.androlib.ApkDecoder(new File(apkPath));
		decoder.setOutDir(new File(apkPath.replaceAll("\\.apk", "")));
		decoder.setForceDelete(true);
		decoder.decode();
		decoder.close();

		System.out.println("Finished decoding APK");
	}

	public static String[] findPasswordIds(String path) throws Exception {
		String[] ret = {};

		for (File folder : new File(path).listFiles()) {
			// Check every folder contains layout
			if (folder.isDirectory() && folder.getName().contains("layout")) {
				// Check every xml file
				for (File file : folder.listFiles()) {
					if (FilenameUtils.getExtension(file.getName()).contains("xml")) {
						Document document = new SAXReader().read(file.getAbsolutePath());
						String[] cur = treeWalk(document.getRootElement());

						// Output and add unique elements to ret
						for (int i = 0; i < cur.length; i++) {
							System.out.println("Find " + cur[i] + " in " + file.getAbsolutePath());

							if (!ArrayUtils.contains(ret, cur[i])) {
								ret = ArrayUtils.add(ret, cur[i]);
							}
						}
					}
				}
			}
		}

		return ret;
	}

	public static String[] treeWalk(Element element) {
		String[] ret = {};

		for (int i = 0, size = element.nodeCount(); i < size; i++) {
			Node node = element.node(i);
			if (node instanceof Element) {
				// Find attribute android:inputType with value textPassword
				for (Iterator<Attribute> it = ((Element) node).attributeIterator(); it.hasNext();) {
					Attribute attribute = (Attribute) it.next();
					if (attribute.getName().equals("inputType") && attribute.getValue().equals("textPassword")) {
						// Find the id of the current control
						for (Iterator<Attribute> itInner = ((Element) node).attributeIterator(); itInner.hasNext();) {
							Attribute attributeInner = (Attribute) itInner.next();
							if (attributeInner.getName().equals("id")) {
								ret = ArrayUtils.addAll(ret, attributeInner.getValue().replaceAll("@id/", "R\\$id: int "));
							}
						}
					}
				}

				// Traverse through the tree
				ret = ArrayUtils.addAll(ret, treeWalk((Element) node));
			}
		}

		return ret;
	}

	public static void main(String[] args) throws Exception {
		// Get the name of APK and the path to Apktool
		String apkPath = "";
		boolean noSoot = false;
		for (int s = 0; s < args.length; s++) {
			if (args[s].contains(".apk")) {
				apkPath = args[s];
			}
			if (args[s].contains("-nosoot")) {
				noSoot = true;
				// Drop this element from args
				args = ArrayUtils.removeElement(args, args[s]);
				s--;
				continue;
			}
		}

		// Decode APK
		apkTool(apkPath);

		if (noSoot) {
			return;
		}
		
		// Options for Soot
		Options.v().set_src_prec(Options.src_prec_apk); // Target to input APK
		Options.v().set_output_format(Options.output_format_jimple); // Output jimple
		Options.v().set_output_dir(apkPath.replaceAll("\\.apk","") + "\\soot");
		Options.v().set_process_multiple_dex(true);

		// Inject taint analysis
		/*
		PackManager.v().getPack("jtp").add(new Transform("jtp.myTransform", new BodyTransformer() {
			protected void internalTransform(Body body, String phase, Map options) {
				new TaintAnalysisWrapper(new ExceptionalUnitGraph(body), passwordIds);
			}
		}));
		*/

		// Entry point for Soot
		soot.Main.main(args);
	}
}

class TaintAnalysisWrapper {
	public TaintAnalysisWrapper(UnitGraph graph, String[] passwordIds) {
		TaintAnalysis analysis = new TaintAnalysis(graph, passwordIds);
	}
}

interface GetUseBoxes {
	public List<ValueBox> getUseBoxes();
}

class TaintAnalysis extends ForwardFlowAnalysis<Unit, Set<Value>> {
	String[] passwordIds;

	public TaintAnalysis(UnitGraph graph, String[] passwordIds) {
		super(graph);

		this.passwordIds = passwordIds;

		doAnalysis();
	}

	@Override
	protected Set<Value> newInitialFlow() {
		return new HashSet();
	}

	@Override
	protected Set<Value> entryInitialFlow() {
		return new HashSet();
	}

	@Override
	protected void copy(Set<Value> src, Set<Value> dest) {
		dest.removeAll(dest);
		dest.addAll(src);
	}

	@Override
	protected void merge(Set<Value> in1, Set<Value> in2, Set<Value> out) {
		out.removeAll(out);
		out.addAll(in1);
		out.addAll(in2);
	}

	@Override
	protected void flowThrough(Set<Value> in, Unit node, Set<Value> out) {
		out.removeAll(out);
		out.addAll(in); // Add origin flow-in tainted value
		out.addAll(checkTainted(in, node)); // Add new tainted values by this node
		
		checkSink(in, node);
	}

	private Set<Value> checkTainted(Set<Value> in, Unit node) {
		Set<Value> ret = new HashSet();
		
		if (checkContains(in, node)) {
			if (node instanceof AssignStmt) {
				ret.add(((AssignStmt)node).getLeftOpBox().getValue());
			} else if (node instanceof IfStmt) {
				if (((IfStmt)node).getTarget() instanceof AssignStmt) {
					ret.add(((AssignStmt)((IfStmt)node).getTarget()).getLeftOpBox().getValue());
				}
			}
		} else if (node instanceof AssignStmt) {
			if (checkSource(((AssignStmt)node).getLeftOpBox().getValue())) {
				ret.add(((AssignStmt)node).getRightOpBox().getValue());
			} else if (checkSource(((AssignStmt)node).getRightOpBox().getValue())) {
				ret.add(((AssignStmt)node).getLeftOpBox().getValue());
			}
		}
		
		return ret;
	}
	
	private boolean checkContains(Set<Value> in, Unit node) {
		for (Value v : in) {
			for (ValueBox b : node.getUseBoxes()) {
				if (b.getValue().equals(v)) {
					return true;
				}
			}
		}
		return false;
	}
	
	private boolean checkSource(Value v) {
		System.out.println(v.toString());
		for (String s : passwordIds) {
			if (v.toString().contains(s)) {
				System.out.println(v.toString());
				return true;
			}
		}
		return false;
	}
	
	private void checkSink(Set<Value> in, Unit node) {
		for (Value v : in) {
			if (node.toString().contains(v.toString())) {
				System.out.println(node.toString());
				return;
			}
		}
	}
	
	/*
	protected Set<Value> stillTaintedValue(Set<Value> in, Unit node) {
		return in;
	}

	protected boolean containsValues(Collection<Value> vs, Object s) {
		for (Value v : vs) {
			if (containsValue(v, s)) {
				return true;
			}
		}
		return false;
	}

	protected boolean containsValue(Value v, Object s) {
		try {
			// I'm so sorry.
			Method m = s.getClass().getMethod("getUseBoxes");
			for (ValueBox b : (Collection<ValueBox>) m.invoke(s))
				if (b.getValue().equals(v))
					return true;
			return false;
		} catch (Exception e) {
			return false;
		}
	}

	protected Set<Value> newTaintedValues(Set<Value> in, Unit node) {
		Set<Value> out = new HashSet();

		if (containsValues(in, node)) {
			if (node instanceof AssignStmt) {
				out.add(((AssignStmt) node).getLeftOpBox().getValue());
			} else if (node instanceof IfStmt) {
				IfStmt i = (IfStmt) node;
				if (i.getTarget() instanceof AssignStmt)
					out.add(((AssignStmt) i.getTarget()).getLeftOpBox().getValue());
			}
		} else if (node instanceof AssignStmt) {
			AssignStmt assn = (AssignStmt) node;

			if (isPrivateSource(assn.getRightOpBox().getValue()))
				out.add(assn.getLeftOpBox().getValue());
		}

		return out;
	}

	protected boolean isPrivateSource(Value u) {
		if (u instanceof VirtualInvokeExpr) {
			VirtualInvokeExpr e = (VirtualInvokeExpr) u;

			for (Value arg : e.getArgs()) {
				if (ArrayUtils.contains(passwordIds, arg.toString())) {
					return true;
				}
			}
		}

		return false;
	}

	protected boolean isTaintedPublicSink(Unit u, Set<Value> in) {
		if (u instanceof InvokeStmt) {
			InvokeExpr e = ((InvokeStmt) u).getInvokeExpr();
			SootMethod m = e.getMethod();
			if (m.getName().equals("println") && m.getDeclaringClass().getName().equals("java.io.PrintStream")
					&& containsValues(in, e))
				return true;
		}

		return false;
	}
	*/
}