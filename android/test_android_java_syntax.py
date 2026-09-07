#!/usr/bin/env python3
"""Parse all Android Java sources with javac before costly native dependency builds.

This deliberately invokes JavacTask.parse(), not type analysis: it needs no
Android SDK or native AARs and does not substitute for assembling the actual APK.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
PARSER = r'''
import com.sun.source.util.JavacTask;
import javax.tools.Diagnostic;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;

public final class AndroidSyntaxParser {
    public static void main(String[] paths) throws Exception {
        if (paths.length == 0) throw new IllegalArgumentException("No Java sources supplied.");
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) throw new IllegalStateException("A JDK is required for syntax verification.");
        DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
        try (StandardJavaFileManager files = compiler.getStandardFileManager(
                diagnostics, Locale.ROOT, StandardCharsets.UTF_8)) {
            JavacTask task = (JavacTask) compiler.getTask(null, files, diagnostics,
                    Arrays.asList("-proc:none", "--release", "17"), null,
                    files.getJavaFileObjectsFromStrings(Arrays.asList(paths)));
            for (Object ignored : task.parse()) { /* Force every source to parse. */ }
        }
        boolean failed = false;
        for (Diagnostic<? extends JavaFileObject> item : diagnostics.getDiagnostics()) {
            if (item.getKind() != Diagnostic.Kind.ERROR) continue;
            failed = true;
            System.err.println(item.getSource().getName() + ":" + item.getLineNumber()
                    + ":" + item.getColumnNumber() + ": " + item.getMessage(Locale.ROOT));
        }
        if (failed) System.exit(1);
    }
}
'''


def main() -> None:
    for tool in ("javac", "java"):
        if not shutil.which(tool):
            raise RuntimeError(f"{tool} is required; the Android syntax gate cannot be skipped.")
    sources = sorted((ROOT / "app" / "src").rglob("*.java"))
    if not sources:
        raise RuntimeError("No Android Java sources were found.")
    with tempfile.TemporaryDirectory(prefix="routervpn-java-syntax-") as directory:
        temp = Path(directory)
        parser = temp / "AndroidSyntaxParser.java"
        parser.write_text(PARSER, encoding="utf-8")
        subprocess.run(["javac", "-d", str(temp), str(parser)], check=True, timeout=30)
        command = ["java", "-cp", str(temp), "AndroidSyntaxParser"]
        # This is the malformed while condition that escaped token-only checks.
        # The negative control proves the parser rejects it without SDK classes.
        broken = temp / "Broken.java"
        broken.write_text("class Broken { void test() { while (true;) {} } }", encoding="utf-8")
        rejected = subprocess.run(command + [str(broken)], capture_output=True, text=True, timeout=30)
        if rejected.returncode != 1 or "Broken.java:" not in rejected.stderr:
            raise RuntimeError("The Java syntax negative control was not rejected correctly.")
        subprocess.run(command + [str(path) for path in sources], check=True, timeout=60)
    print(f"Android Java syntax: PASS ({len(sources)} sources; APK type/build checks still required)")


if __name__ == "__main__":
    main()
