package eece512;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import soot.jimple.infoflow.android.TestApps.Test;

public class ApkTester {
	/*
	 * args[0]: root folder
	 * args[1]: apktool.jar
	 * args[2]: Android platforms
	 * args[3]: (Optional) staring point
	 */
	public static void main(String[] args) throws Exception {
		String startPoint = null;
		if (args.length < 3) {
			System.out.println("Not enough arguments!");
		} else if (args.length == 4) {
			startPoint = args[3];
		}
		
		// Find APKs from input folder
		File rootDir = new File(args[0]);
		ArrayList<File> apkList = findApk(rootDir);
		
		ArrayList<String> detectedApk = new ArrayList<String>();
		for (File f : apkList) {
			// Skip until starting point detected
			if (startPoint != null && !startPoint.equals(f.toString())) {
				continue;
			} else {
				startPoint = null;
			}
			
			// Generate input parameters for ApkDecoder
			ArrayList<String> apkDecoderInputs = new ArrayList<String>();
			apkDecoderInputs.add(args[1]);
			apkDecoderInputs.add("-android-jars");
			apkDecoderInputs.add(args[2]);
			apkDecoderInputs.add("-allow-phantom-refs");
			apkDecoderInputs.add("-x");
			apkDecoderInputs.add("android.*");
			apkDecoderInputs.add("-process-dir");
			apkDecoderInputs.add(f.toString());
			apkDecoderInputs.add("-nosoot");
			// Run ApkDecoder
			ApkDecoder.main(apkDecoderInputs.toArray(new String[apkDecoderInputs.size()]));
			// Find EditText for password inputs
			String[] passwordIds = ApkDecoder.findPasswordIds(f.toString().replaceAll("\\.apk", "") + "\\res");
			// If there is detected password EditText, add it for double check
			if (passwordIds.length > 0) {
				detectedApk.add(f.toString());
			} else {
				System.out.println("No password EditText detected, skipped");
				continue;
			}
			// Generate input parameters for FlowDroid
			ArrayList<String> flowDroidInputs = new ArrayList<String>();
			flowDroidInputs.add(f.toString());
			flowDroidInputs.add(args[2]);
			flowDroidInputs.add("--pathalgo");
			flowDroidInputs.add("CONTEXTSENSITIVE");
			flowDroidInputs.add("--paths");
			flowDroidInputs.add("--aplength");
			flowDroidInputs.add("100");
			// Run FlowDroid
			Test.main(flowDroidInputs.toArray(new String[flowDroidInputs.size()]));
		}
		
		// Write detected APKs to file
		FileWriter fileWriter = new FileWriter("list.txt");
	    PrintWriter printWriter = new PrintWriter(fileWriter);
	    for (String apk : detectedApk) {
	    	printWriter.println(apk);
	    }
	    printWriter.close();
	}
	 
	public static ArrayList<File> findApk(File dir){
		ArrayList<File> ret = new ArrayList<File>();
	    for(File f: dir.listFiles()){
	        if(f.isFile() && f.toString().contains(".apk")){
	        	System.out.println("Add " + f.toString() + " to list");
	        	ret.add(f);
	        }else if(f.isDirectory()){
	        	ret.addAll(findApk(f));
	        }
	    }
	    return ret;
	}
}
