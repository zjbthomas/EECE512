package eece512;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import soot.jimple.infoflow.android.TestApps.Test;

public class BatchApkTester {
	final static int ARGSLENGTH = 3;
	final static int APLENGTH = 100;
	
	/*
	 * args[0]: root folder
	 * args[1]: Android platforms
	 * args[2]: (Optional) staring point
	 */
	public static void main(String[] args) {
		String startPoint = null;
		if (args.length < ARGSLENGTH) {
			System.out.println("Not enough arguments!");
		} else if (args.length == ARGSLENGTH) {
			startPoint = args[ARGSLENGTH - 1];
		}
		
		// Find APKs from input folder
		File rootDir = new File(args[0]);
		ArrayList<File> apkList = findApk(rootDir);
		
		ArrayList<String> detectedApk = new ArrayList<String>();
		ArrayList<String> errorApk = new ArrayList<String>();
		for (File f : apkList) {
			// Skip until starting point detected
			if (startPoint != null && !startPoint.equals(f.toString())) {
				continue;
			} else {
				startPoint = null;
			}
			
			// Run apkTester
			try {
				String[] passwordIds = apkTester(f.toString(), args[1], true);
				if (passwordIds.length > 0) {
					detectedApk.add(f.toString());
				} else {
					System.out.println("No password EditText detected, skipped");
					continue;
				}
			} catch (Exception e) {
				e.printStackTrace();
				errorApk.add(f.toString());
				continue;
			}
		}
		
		// Write to file
		try {
			FileWriter fileWriter;
			fileWriter = new FileWriter("list.txt");
		    PrintWriter printWriter = new PrintWriter(fileWriter);
		    // Write detected APKs
		    printWriter.println("APKs with EditText for passwords:");
		    for (String apk : detectedApk) {
		    	printWriter.println(apk);
		    }
		    // Write error APKs
		    printWriter.println("\nAPKs cannot be analysed automatically (with error):");
		    for (String apk : detectedApk) {
		    	printWriter.println(apk);
		    }
		    printWriter.close();
		} catch (Exception e) {
			e.printStackTrace();;
		}
	}
	 
	public static ArrayList<File> findApk(File dir){
		ArrayList<File> ret = new ArrayList<File>();
	    for(File f: dir.listFiles()){
	        if(f.isFile() && f.toString().contains(".apk")){
	        	//System.out.println("Add " + f.toString() + " to list");
	        	ret.add(f);
	        }else if(f.isDirectory()){
	        	ret.addAll(findApk(f));
	        }
	    }
	    return ret;
	}
	
	public static String[] apkTester(String apkPath, String sdkPath, boolean noSoot) throws Exception {
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
		String[] passwordIds;
		passwordIds = ApkDecoder.findPasswordIds(apkPath.replaceAll("\\.apk", "") + "\\res");
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
		// Return passwordIds
		return passwordIds;
	}
}
