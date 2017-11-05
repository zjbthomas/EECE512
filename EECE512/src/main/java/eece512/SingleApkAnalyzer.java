package eece512;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;

import soot.jimple.infoflow.android.TestApps.ResultsHandler;
import soot.jimple.infoflow.android.TestApps.Test;

public class SingleApkAnalyzer {
	/*
	 * args[0]: APK path
	 * args[1]: Android platforms
	 */
	public static void main(String[] args) throws Exception {
		// Run APK decoder
		String[] passwordIds = BatchApkTester.decodeApk(args[0], args[1], false);
		// Run obfuscation detection
		if (BatchApkTester.detectObfuscation(new File(args[0].replaceAll("\\.apk", "")))) {
			System.out.println("[IMPORTANT] Obfuscation detected");
		}
		// Run FlowDroid
		BatchApkTester.flowDroid(args[0], args[1]);
		// Find digital ID corresponding to String ID
		HashMap<Integer, String> digitalIds = ApkDecoder.findDigitalIds(args[0].replaceAll("\\.apk", "") + "\\soot", passwordIds);
		// Feed digital ID into ResultsHanlder
		ResultsHandler.feedPasswordIds(digitalIds);
		// Handle results
		ResultsHandler.handleResults();
	}
}
