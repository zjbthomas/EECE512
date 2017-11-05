package eece512;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
							if (!ArrayUtils.contains(ret, cur[i])) {
								System.out.println("[IMPORTANT] Find " + cur[i] + " in " + file.getAbsolutePath());
								ret = ArrayUtils.add(ret, cur[i]);
							} else {
								System.out.println("[IMPORTANT] Find duplicated " + cur[i] + " in " + file.getAbsolutePath() + ", skipped");
							}
						}
					}
				}
			}
		}
		
		System.out.println("[IMPORTANT] Total number of unique controls found: " + ret.length);
		System.out.println("---");
		
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
								ret = ArrayUtils.addAll(ret, attributeInner.getValue().replaceAll("@id/", ""));
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
		soot.G.reset();
		Options.v().set_src_prec(Options.src_prec_apk); // Target to input APK
		Options.v().set_output_format(Options.output_format_jimple); // Output jimple
		Options.v().set_output_dir(apkPath.replaceAll("\\.apk","") + "\\soot");
		Options.v().set_process_multiple_dex(true);

		// Entry point for Soot
		soot.Main.main(args);
	}
	
	public static HashMap<Integer, String> findDigitalIds(String sootPath, String[] passwordIds) throws Exception {
		HashMap<Integer, String> ret = new HashMap<Integer, String>();
		
		for (File f : new File(sootPath).listFiles()) {
			if (f.toString().contains("R$id.jimple")) {
				BufferedReader br = new BufferedReader(new FileReader(f));
	            String readLine;
	            while ((readLine = br.readLine()) != null) {
	                for (String s : passwordIds) {
	                	// Extend id to idWithRid
	                	String idWithRid = "R$id: int " + s;
	                	
	                	if (readLine.contains(s)) {
	                		// Use regex to find ID
	                		int id = 0;
	                		
	                		Pattern r = Pattern.compile("= [0-9]+");
	                		Matcher m = r.matcher(readLine);
	                		if (m.find()) {
	                			id = Integer.parseInt(readLine.substring(m.start() + 2, m.end()));
	                			if (ret.containsKey(id)) {
                					System.out.println("[IMPORTANT] " + id + " is already mapped, but appears in " + readLine);
                					break;
                				}
	                		} else {
	                			//System.out.println("[IMPORTANT] No IDs found in " + readLine);
	                			break;
	                		}
	                		
	                		// Use regex to find qualified id
	                		String qId = "";
	                		
	                		r = Pattern.compile("<.+>");
	                		m = r.matcher(readLine);
	                		if (m.find()) {
	                			qId = readLine.substring(m.start() + 1, m.end() - 1);
	                		} else {
	                			System.out.println("[IMPORTANT] Qualified ID not found in " + readLine + ", skipped");
	                			break;
	                		}
	                		
	                		// Check if qId exists
	                		if (ret.containsValue(qId)) {
	                			System.out.println("[IMPORTANT] " + qId + " is already mapped, but appears in " + readLine);
	                			break;
	                		}
	                		
	                		// Creating mapping
	                		System.out.println("[IMPORTANT] Map " + qId + " to ID " + id);
            				ret.put(id, qId);
            				break;
	                	}
	                }
	            }
	            br.close();
			}
		}
		
		System.out.println("---");
		
		return ret;
	}
}