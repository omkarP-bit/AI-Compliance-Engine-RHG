from rhg.mutator.patch_engine import PatchEngine


class TestPatchEngine:
    def setup_method(self):
        self.engine = PatchEngine()

    def test_replace_existing_value(self):
        artifact = {"spec": {"containers": [{"securityContext": {"privileged": True}}]}}
        patches = [{"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False}]
        patched, ops = self.engine.apply_patches(artifact, patches)
        assert patched["spec"]["containers"][0]["securityContext"]["privileged"] is False
        assert len(ops) == 1

    def test_add_missing_field(self):
        artifact = {"spec": {"containers": [{"name": "app", "securityContext": {}}]}}
        patches = [{"op": "add", "path": "/spec/containers/0/securityContext/runAsNonRoot", "value": True}]
        patched, _ = self.engine.apply_patches(artifact, patches)
        assert patched["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] is True

    def test_remove_field(self):
        artifact = {"spec": {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}}
        patches = [{"op": "remove", "path": "/spec/containers/0/securityContext/privileged"}]
        patched, _ = self.engine.apply_patches(artifact, patches)
        assert "privileged" not in patched["spec"]["containers"][0]["securityContext"]

    def test_multiple_patches_applied_in_order(self):
        artifact = {
            "spec": {
                "containers": [
                    {"name": "app", "securityContext": {"privileged": True, "runAsUser": 0}}
                ]
            }
        }
        patches = [
            {"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False},
            {"op": "replace", "path": "/spec/containers/0/securityContext/runAsUser", "value": 1000},
        ]
        patched, ops = self.engine.apply_patches(artifact, patches)
        sc = patched["spec"]["containers"][0]["securityContext"]
        assert sc["privileged"] is False
        assert sc["runAsUser"] == 1000
        assert len(ops) == 2

    def test_original_artifact_not_mutated(self):
        original = {"spec": {"containers": [{"securityContext": {"privileged": True}}]}}
        patches = [{"op": "replace", "path": "/spec/containers/0/securityContext/privileged", "value": False}]
        patched, _ = self.engine.apply_patches(original, patches)
        assert original["spec"]["containers"][0]["securityContext"]["privileged"] is True

    def test_diff_detects_changes(self):
        before = {"spec": {"privileged": True}}
        after = {"spec": {"privileged": False}}
        changes = self.engine.diff(before, after)
        assert any(c["path"] == "/spec/privileged" for c in changes)

    def test_diff_returns_empty_for_identical(self):
        doc = {"spec": {"containers": [{"name": "app"}]}}
        assert self.engine.diff(doc, doc) == []

    def test_create_path_when_intermediate_missing(self):
        artifact = {"spec": {}}
        patches = [{"op": "add", "path": "/spec/containers/0/securityContext/runAsNonRoot", "value": True}]
        patched, ops = self.engine.apply_patches(artifact, patches)
        assert patched["spec"]["containers"][0]["securityContext"]["runAsNonRoot"] is True
        assert any("create+set" in op for op in ops)

    def test_apply_patches_with_list_index(self):
        artifact = {"containers": [{"name": "a"}, {"name": "b"}]}
        patches = [{"op": "replace", "path": "/containers/1/name", "value": "fixed"}]
        patched, _ = self.engine.apply_patches(artifact, patches)
        assert patched["containers"][1]["name"] == "fixed"

    def test_diff_added_keys(self):
        before = {"a": 1}
        after = {"a": 1, "b": 2}
        changes = self.engine.diff(before, after)
        assert any(c["op"] == "add" and c["path"] == "/b" for c in changes)

    def test_diff_removed_keys(self):
        before = {"a": 1, "b": 2}
        after = {"a": 1}
        changes = self.engine.diff(before, after)
        assert any(c["op"] == "remove" and c["path"] == "/b" for c in changes)
