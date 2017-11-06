package eece512;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.dom4j.Attribute;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.Node;
import org.dom4j.io.SAXReader;

import soot.jimple.infoflow.android.TestApps.ResultsHandler;
import soot.jimple.infoflow.android.TestApps.Test;

public class BatchApkTester {
	final static int ARGSLENGTH = 2;
	final static int APLENGTH = 100;
	
	/*
	 * args[0]: root folder
	 * args[1]: Android platforms
	 * args[2]: (Optional) staring point
	 */
	public static void main(String[] args) throws Exception {
		String startPoint = null;
		if (args.length < ARGSLENGTH) {
			System.out.println("Not enough arguments!");
			return;
		} else if (args.length == ARGSLENGTH + 1) {
			startPoint = args[ARGSLENGTH];
		}
		
		// Find APKs from input folder
		File rootDir = new File(args[0]);
		ArrayList<File> apkList = findApk(rootDir, 2);
		
		ArrayList<String> detectedApk = new ArrayList<String>();
		ArrayList<String> errorApk = new ArrayList<String>();
		ArrayList<String> obfuscationApk = new ArrayList<String>();
		for (File f : apkList) {
			// Skip until starting point detected
			if (startPoint != null && !startPoint.equals(f.toString())) {
				continue;
			} else {
				startPoint = null;
			}
			
			try {
				// Print separator
				System.out.println("---");
				// Run APK decoder
				String[] passwordIds = decodeApk(f.toString(), args[1], true);
				// Skip if no EditText for password found
				if (passwordIds.length > 0) {
					detectedApk.add(f.toString());
				} else {
					System.out.println("[IMPORTANT] No password EditText detected, skipped");
					FileUtils.deleteDirectory(new File(f.toString().replaceAll("\\.apk", "")));
					continue;
				}
				// Run obfuscation detection
				if (detectObfuscation(new File(f.toString().replaceAll("\\.apk", "")))) {
					obfuscationApk.add(f.toString());
					System.out.println("[IMPORTANT] Obfuscation detected");
				}
				// Run FlowDroid
				flowDroid(f.toString(), args[1]);
				// Find digital ID corresponding to String ID
				HashMap<Integer, String> digitalIds = ApkDecoder.findDigitalIds(args[0].replaceAll("\\.apk", "") + "\\soot", passwordIds);
				// Feed digital ID into ResultsHanlder
				ResultsHandler.feedPasswordIds(digitalIds);
				// Handle results
				ResultsHandler.handleResults();
				// Delete folder
				FileUtils.deleteDirectory(new File(f.toString().replaceAll("\\.apk", "")));
			} catch (Exception e) {
				e.printStackTrace();
				errorApk.add(f.toString());
				FileUtils.deleteDirectory(new File(f.toString().replaceAll("\\.apk", "")));
				continue;
			}
		}
		
		// Write to file
		try {
			FileWriter fileWriter;
			fileWriter = new FileWriter("list.txt");
		    PrintWriter printWriter = new PrintWriter(fileWriter);
		    // Write Statistics
		    printWriter.println("Total number of APKs: " + apkList.size());
		    printWriter.println("Number of APKs cannot be analysed automatically(with error): " + errorApk.size());
		    printWriter.println("Number of APKs with EditText for passwords: " + detectedApk.size());
		    printWriter.println("Number of obfuscated APKs: " + obfuscationApk.size());
		    printWriter.println("Success Rate:" + ((double)(apkList.size() - errorApk.size()) / apkList.size()));
		    printWriter.println("Detect Rate:" + ((double)detectedApk.size() / (apkList.size() - errorApk.size())));
		    printWriter.println("Obfuscation Rate:" + ((double)obfuscationApk.size() / (apkList.size() - errorApk.size())));
		    // Write detected APKs
		    printWriter.println("\nAPKs with EditText for passwords:");
		    for (String apk : detectedApk) {
		    	printWriter.println(apk);
		    }
		    // Write APKs with obfuscation
		    printWriter.println("\nAPK with obobfuscation:");
		    for (String apk : obfuscationApk) {
		    	printWriter.println(apk);
		    }
		    // Write error APKs
		    printWriter.println("\nAPKs cannot be analysed automatically (with error):");
		    for (String apk : errorApk) {
		    	printWriter.println(apk);
		    }
		    printWriter.close();
		} catch (Exception e) {
			e.printStackTrace();;
		}
	}
	 
	public static ArrayList<File> findApk(File dir, int depth) throws Exception{
		ArrayList<File> ret = new ArrayList<File>();
	    for(File f: dir.listFiles()){
	        if(f.isFile() && f.toString().contains(".apk")){
	        	System.out.println("Add " + f.toString() + " to list");
	        	ret.add(f);
	        	
	        	// Pre-delete folder
	    		FileUtils.deleteDirectory(new File(f.toString().replaceAll("\\.apk", "")));
	        }else if(f.isDirectory() && depth != 1){
	        	ret.addAll(findApk(f, depth - 1));
	        }
	    }
	    return ret;
	}
	
	public static String[] decodeApk(String apkPath, String sdkPath, boolean noSoot) throws Exception {
		// Generate input parameters for ApkDecoder
		ArrayList<String> apkDecoderInputs = new ArrayList<String>();
		apkDecoderInputs.add("-android-jars");
		apkDecoderInputs.add(sdkPath);
		apkDecoderInputs.add("-allow-phantom-refs");
		apkDecoderInputs.add("-x");
		apkDecoderInputs.add("android.*");
		apkDecoderInputs.add("-process-dir");
		apkDecoderInputs.add(apkPath);
		if (noSoot) {
			apkDecoderInputs.add("-nosoot");
		}
		// Run ApkDecoder
		ApkDecoder.main(apkDecoderInputs.toArray(new String[apkDecoderInputs.size()]));
		// Find EditText for password inputs
		return ApkDecoder.findPasswordIds(apkPath.replaceAll("\\.apk", "") + "\\res");
	}
	
	public static void flowDroid(String apkPath, String sdkPath) throws Exception {
		// Reset repeat count
		Test.resetRepeatCount();
		// Generate input parameters for FlowDroid
		ArrayList<String> flowDroidInputs = new ArrayList<String>();
		flowDroidInputs.add(apkPath);
		flowDroidInputs.add(sdkPath);
		flowDroidInputs.add("--pathalgo");
		flowDroidInputs.add("CONTEXTSENSITIVE");
		flowDroidInputs.add("--paths");
		flowDroidInputs.add("--aplength");
		flowDroidInputs.add(String.valueOf(APLENGTH));
		// Run FlowDroid
		Test.main(flowDroidInputs.toArray(new String[flowDroidInputs.size()]));
	}
	
	/*
	 * Input should be the root folder of APKTool
	 */
	public static boolean detectObfuscation(File dir) {
		for(File f: dir.listFiles()){
			if (f.isDirectory() && f.toString().contains("smali")) {
				if (detectObfuscationInSmali(f)) {
					return true;
				}
			}
	    }
		return false;
	}
	
	public static boolean detectObfuscationInSmali(File dir) {
		for(File f: dir.listFiles()){
			if (f.isDirectory()) {
				return detectObfuscationInSmali(f);
			} else if (f.getAbsolutePath().contains("\\a.smali")) {
				return true;
			}
	    }
		return false;
	}
}
