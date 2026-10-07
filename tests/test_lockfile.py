from verify import diffparse
from verify.authorities.lockfile_policy import evaluate

NPM_DIFF = """\
diff --git a/package-lock.json b/package-lock.json
--- a/package-lock.json
+++ b/package-lock.json
@@ -10,8 +10,8 @@
     "node_modules/left-pad": {
-      "version": "1.2.0",
-      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz",
+      "version": "1.3.0",
+      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
       "integrity": "sha512-abc"
     },
+    "node_modules/tiny-helper": {
+      "version": "0.0.9",
+      "resolved": "https://mirror.example.net/tiny-helper/-/tiny-helper-0.0.9.tgz"
+    },
"""

REQ_DIFF = """\
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,3 +1,3 @@
-requests==2.30.0
+requests==2.32.4
 urllib3==2.2.1
"""


def test_npm_versions_for_target():
    prior, chosen = diffparse.versions_for(NPM_DIFF, "left-pad", "npm")
    assert (prior, chosen) == ("1.2.0", "1.3.0")


def test_npm_versions_for_missing_package():
    assert diffparse.versions_for(NPM_DIFF, "not-here", "npm") == (None, None)


def test_requirements_versions():
    assert diffparse.versions_for(REQ_DIFF, "Requests", "PyPI") == ("2.30.0", "2.32.4")


def test_packages_in_diff():
    assert diffparse.packages_in_diff(NPM_DIFF, "npm") == {"left-pad", "tiny-helper"}


def test_lockfile_policy_flags_host_and_undeclared():
    r = evaluate(NPM_DIFF, "npm", declared=("left-pad",), allowed_hosts=("registry.npmjs.org",))
    assert r.files == ["package-lock.json"]
    assert r.hosts_added == ["mirror.example.net", "registry.npmjs.org"]
    assert r.disallowed_hosts == ["mirror.example.net"]
    assert r.packages_touched == ["left-pad", "tiny-helper"]
    assert r.undeclared_packages == ["tiny-helper"]


def test_lockfile_policy_clean():
    clean = NPM_DIFF.split('+    "node_modules/tiny-helper"')[0]
    r = evaluate(clean, "npm", declared=("left-pad",), allowed_hosts=("registry.npmjs.org",))
    assert r.disallowed_hosts == [] and r.undeclared_packages == []
