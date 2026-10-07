"""Public PR replay helpers (review finding R2-17)."""
from collections import Counter

from harness.replay import filter_lockfile_sections, tabulate

PR_DIFF = """\
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-old https://example.com
+new https://evil.example
diff --git a/package.json b/package.json
--- a/package.json
+++ b/package.json
@@ -5 +5 @@
-    "left-pad": "^1.2.0"
+    "left-pad": "^1.3.0"
diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -10,6 +10,6 @@
     "node_modules/left-pad": {
-      "version": "1.2.0",
+      "version": "1.3.0",
     },
"""


def test_filter_keeps_only_lockfiles():
    kept = filter_lockfile_sections(PR_DIFF)
    assert "package-lock.json" in kept
    assert "README.md" not in kept and "evil.example" not in kept
    assert "package.json b/package.json" not in kept


def test_tabulate_by_label():
    rows = [
        {"label": "legitimate", "verdict": "allow"},
        {"label": "legitimate", "verdict": "block"},
        {"label": "known_bad", "verdict": "block"},
        {"label": "", "verdict": "route_to_human"},
    ]
    t = tabulate(rows)
    assert t["legitimate"] == Counter({"allow": 1, "block": 1})
    assert t["known_bad"] == Counter({"block": 1})
    assert t["unknown"] == Counter({"route_to_human": 1})
