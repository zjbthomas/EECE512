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

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

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
		System.out.println("[IMPORTANT] Decoding APK " + apkPath);

		// Check files exist
		if (!new File(apkPath).exists()) {
			throw new Exception("APK " + apkPath + "not exists");
		}

		// Pre-delete folder
		FileUtils.deleteDirectory(new File(apkPath.replaceAll("\\.apk", "")));
		
		// Run ApkTool
		brut.androlib.ApkDecoder decoder = new brut.androlib.ApkDecoder(new File(apkPath));
		decoder.setOutDir(new File(apkPath.replaceAll("\\.apk", "")));
		decoder.setForceDelete(true);
		decoder.decode();
		decoder.close();
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
							System.out.println("[IMPORTANT] Find " + cur[i] + " in " + file.getAbsolutePath());

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

		// Entry point for Soot
		soot.Main.main(args);
	}
}