package eece512;

import java.util.ArrayList;

import soot.jimple.infoflow.android.TestApps.Test;

public class SingleApkAnalyzer {
	/*
	 * args[0]: APK path
	 * args[1]: Android platforms
	 */
	public static void main(String[] args) throws Exception {
		BatchApkTester.apkTester(args[0], args[1], false);
	}
}
