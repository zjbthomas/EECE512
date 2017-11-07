package eece512;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;

import org.apache.commons.io.FileUtils;

import soot.jimple.infoflow.android.TestApps.ResultsHandler;

public class FileApkTester {
	final static int ARGSLENGTH = 2;
	final static boolean DELETEDIR = true;
	
	/*
	 * args[0]: APKs list file
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
		
		// Read APKs from list file
		BufferedReader br = new BufferedReader(new FileReader(args[0]));
        String readLine;
        while ((readLine = br.readLine()) != null) {
        	// Skip until starting point detected
			if (startPoint != null && !startPoint.equals(readLine)) {
				continue;
			} else {
				startPoint = null;
			}
			
			try {
				// Print separator
				System.out.println("------");
				// Run APK decoder
				String[] passwordIds = BatchApkTester.decodeApk(readLine, args[1]);
				// Skip if no EditText for password found
				if (passwordIds.length <= 0) {
					System.out.println("[IMPORTANT] No password EditText detected, skipped");
					if (DELETEDIR) {
						FileUtils.deleteDirectory(new File(readLine.replaceAll("\\.apk", "")));
					}
					continue;
				}
				// Run obfuscation detection
				if (BatchApkTester.detectObfuscation(new File(readLine.replaceAll("\\.apk", "")))) {
					System.out.println("[IMPORTANT] Obfuscation detected");
				}
				// Run FlowDroid
				BatchApkTester.flowDroid(readLine, args[1], passwordIds);
				// Delete folder
				if (DELETEDIR) {
					FileUtils.deleteDirectory(new File(readLine.replaceAll("\\.apk", "")));
				}
			} catch (Exception e) {
				e.printStackTrace();
				continue;
			}
        }
        br.close();
	}
}
