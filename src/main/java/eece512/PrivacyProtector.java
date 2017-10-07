package eece512;
import java.io.File;
import java.util.Iterator;

import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

import soot.options.Options;


public class PrivacyProtector {
	
	public static void apkTool(String apkPath, String apkToolPath) throws Exception {
		System.out.println("Decoding APK " + apkPath + "...");
		
		// Check files exist
		if (!new File(apkPath).exists()) {
			throw new Exception("APK " + apkPath + "not exists");
		}
		if (!new File(apkToolPath).exists()) {
			throw new Exception("Apktool " + apkToolPath + "not exists");
		}
		
		// Run command line
		Process pr = Runtime.getRuntime().exec("java -jar " + apkToolPath + " d -f " + apkPath + " -o " + apkPath.replaceAll("\\.apk", ""));
		
		// Waiting for result
		if (pr.waitFor() != 0) {
			throw new Exception("Error in decoding APK");
		}
		
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
						ret = ArrayUtils.addAll(ret, cur);
						
						// Output
						for (int i = 0; i < cur.length; i++) {
							System.out.println("Find " + cur[i] + " in " + file.getAbsolutePath());
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
				for (Iterator<Attribute> it = ((Element)node).attributeIterator(); it.hasNext();) {
					Attribute attribute = (Attribute)it.next();
					if (attribute.getName().equals("inputType") && attribute.getValue().equals("textPassword")) {
						// Find the id of the current control
						for (Iterator<Attribute> itInner = ((Element)node).attributeIterator(); itInner.hasNext();) {
							Attribute attributeInner = (Attribute)itInner.next();
							if (attributeInner.getName().equals("id")) {
								ret = ArrayUtils.addAll(ret, attributeInner.getValue().replaceAll("@id/", "R.id."));
							}
						}
					}
				}
				
				// Traverse through the tree
				ret = ArrayUtils.addAll(ret, treeWalk((Element)node));
			}
		}
		
		return ret;
	}
	
	public static void main(String[] args) throws Exception {
		// Get the name of APK and the path to Apktool
		String apkPath = "";
		String apkToolPath = "";
		for (int s = 0; s < args.length; s++) {
			if (args[s].contains(".apk")) {
				apkPath = args[s];
			}
			if (args[s].contains("apktool.jar")) {
				apkToolPath = args[s];
				// Drop this element from args
				args = ArrayUtils.removeElement(args, args[s]);
				s--;
			}
		}
		
		// Decode APK
		apkTool(apkPath, apkToolPath);
		
		// Find EditText for password inputs
		String[] passwordIds = {};
		passwordIds = findPasswordIds(apkPath.replaceAll("\\.apk", "") + "\\res");
		
		// Options for SOOT
		Options.v().set_src_prec(Options.src_prec_apk); // Target to input APK
		
		soot.Main.main(args);
	}
}