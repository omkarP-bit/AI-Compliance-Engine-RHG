from rhg.api.routes import _deduplicate_patches, _is_yaml, _infer_type


class TestDeduplicatePatches:
    def test_deduplicates_by_op_and_path(self):
        patches = [
            {"op": "replace", "path": "/a", "value": 1},
            {"op": "replace", "path": "/a", "value": 2},
            {"op": "add", "path": "/b", "value": 3},
        ]
        result = _deduplicate_patches(patches)
        assert len(result) == 2
        assert result[0]["path"] == "/a"
        assert result[1]["path"] == "/b"

    def test_keeps_first_occurrence(self):
        patches = [
            {"op": "replace", "path": "/x", "value": "first"},
            {"op": "replace", "path": "/x", "value": "second"},
        ]
        result = _deduplicate_patches(patches)
        assert result[0]["value"] == "first"

    def test_returns_empty_for_empty_list(self):
        assert _deduplicate_patches([]) == []

    def test_same_op_different_path_preserved(self):
        patches = [
            {"op": "replace", "path": "/a", "value": 1},
            {"op": "replace", "path": "/b", "value": 2},
        ]
        assert len(_deduplicate_patches(patches)) == 2


class TestIsYaml:
    def test_yaml_extensions(self):
        assert _is_yaml("deploy.yaml") is True
        assert _is_yaml("deploy.yml") is True
        assert _is_yaml("main.tf") is False
        assert _is_yaml("Dockerfile") is False


class TestInferType:
    def test_kubernetes_from_yaml(self):
        assert _infer_type("deploy.yaml") == "kubernetes"
        assert _infer_type("pod.yml") == "kubernetes"

    def test_terraform_from_tf(self):
        assert _infer_type("main.tf") == "terraform"
        assert _infer_type("plan.tf.json") == "terraform"
        assert _infer_type("tfplan.json") == "terraform"

    def test_dockerfile(self):
        assert _infer_type("Dockerfile") == "dockerfile"
        assert _infer_type("app.dockerfile") == "dockerfile"

    def test_fallback_to_kubernetes(self):
        assert _infer_type("unknown.txt") == "kubernetes"
        assert _infer_type("readme.md") == "kubernetes"
