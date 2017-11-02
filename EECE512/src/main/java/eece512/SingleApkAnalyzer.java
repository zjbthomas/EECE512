package eece512;

import java.io.File;
import java.util.ArrayList;

import soot.jimple.infoflow.android.TestApps.Test;

public class SingleApkAnalyzer {
	/*
	 * args[0]: APK path
	 * args[1]: Android platforms
	 */
	public static void main(String[] args) throws Exception {
		// Run APK decoder
		boolean detected = BatchApkTester.decodeApk(args[0], args[1], false, false);
		// Run obfuscation detection
		if (BatchApkTester.detectObfuscation(new File(args[0].replaceAll("\\.apk", "")))) {
			System.out.println("[IMPORTANT] Obfuscation detected");
		}
		// Run FlowDroid
		BatchApkTester.flowDroid(args[0], args[1]);
	}
}
