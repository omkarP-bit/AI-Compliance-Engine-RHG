from ace.parsers.kubernetes import KubernetesParser
from ace.parsers.terraform import TerraformParser
from ace.parsers.dockerfile import DockerfileParser
from ace.parsers.helm import HelmParser

PRIVILEGED_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: test-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            runAsUser: 0
"""

SAFE_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: safe-app
spec:
  template:
    spec:
      containers:
        - name: app
          image: nginx:1.25
          securityContext:
            privileged: false
            runAsNonRoot: true
            runAsUser: 1000
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
"""


class TestKubernetesParser:
    def setup_method(self):
        self.parser = KubernetesParser()

    def test_supports_yaml_files(self):
        assert self.parser.supports("deployment.yaml") is True
        assert self.parser.supports("deployment.yml") is True
        assert self.parser.supports("main.tf") is False

    def test_parse_returns_normalized_artifact(self):
        artifact = self.parser.parse(PRIVILEGED_DEPLOYMENT, "deployment.yaml")
        assert artifact.artifact_type == "kubernetes"
        assert artifact.name == "deployment.yaml"
        assert "containers" in artifact.metadata

    def test_extracts_containers(self):
        artifact = self.parser.parse(PRIVILEGED_DEPLOYMENT, "deployment.yaml")
        containers = artifact.metadata["containers"]
        assert len(containers) == 1
        assert containers[0]["name"] == "app"

    def test_extracts_security_context(self):
        artifact = self.parser.parse(PRIVILEGED_DEPLOYMENT, "deployment.yaml")
        container = artifact.metadata["containers"][0]
        assert container["securityContext"]["privileged"] is True
        assert container["securityContext"]["runAsUser"] == 0

    def test_safe_deployment_has_no_privileged(self):
        artifact = self.parser.parse(SAFE_DEPLOYMENT, "safe.yaml")
        container = artifact.metadata["containers"][0]
        assert container["securityContext"]["privileged"] is False

    def test_metadata_includes_kind_and_namespace(self):
        artifact = self.parser.parse(PRIVILEGED_DEPLOYMENT, "deployment.yaml")
        assert artifact.metadata["kind"] == "Deployment"
        assert artifact.metadata["namespace"] == "default"

    def test_extracts_init_containers(self):
        yaml_with_init = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: init-app
spec:
  template:
    spec:
      initContainers:
        - name: init-svc
          image: busybox
      containers:
        - name: app
          image: nginx
"""
        artifact = self.parser.parse(yaml_with_init, "init.yaml")
        assert len(artifact.metadata["containers"]) == 2

    def test_handles_pod_directly(self):
        pod_yaml = """
apiVersion: v1
kind: Pod
metadata:
  name: direct-pod
spec:
  containers:
    - name: app
      image: nginx
"""
        artifact = self.parser.parse(pod_yaml, "pod.yaml")
        assert artifact.metadata["kind"] == "Pod"
        assert len(artifact.metadata["containers"]) == 1


class TestTerraformParser:
    def setup_method(self):
        self.parser = TerraformParser()

    def test_supports_tf_files(self):
        assert self.parser.supports("main.tf") is True
        assert self.parser.supports("plan.tf.json") is True
        assert self.parser.supports("deploy.yaml") is False

    def test_parse_terraform_plan(self):
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.data",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["create"], "after": {"bucket": "my-data"}},
                }
            ]
        }
        import json
        artifact = self.parser.parse(json.dumps(plan), "plan.tf.json")
        assert artifact.artifact_type == "terraform"
        assert len(artifact.metadata["resources"]) == 1

    def test_filters_noop_changes(self):
        plan = {
            "resource_changes": [
                {
                    "address": "aws_s3_bucket.data",
                    "type": "aws_s3_bucket",
                    "change": {"actions": ["no-op"], "after": {}},
                }
            ]
        }
        import json
        artifact = self.parser.parse(json.dumps(plan), "plan.tf.json")
        assert len(artifact.metadata["resources"]) == 0


class TestDockerfileParser:
    def setup_method(self):
        self.parser = DockerfileParser()

    def test_supports_dockerfile(self):
        assert self.parser.supports("Dockerfile") is True
        assert self.parser.supports("app.dockerfile") is True
        assert self.parser.supports("deploy.yaml") is False

    def test_parse_returns_instructions(self):
        content = "FROM python:3.12\nRUN pip install requests\n"
        artifact = self.parser.parse(content, "Dockerfile")
        assert artifact.artifact_type == "dockerfile"
        assert len(artifact.raw["instructions"]) == 2

    def test_extracts_from_image(self):
        content = "FROM python:3.12-slim\nRUN apt-get update\n"
        artifact = self.parser.parse(content, "Dockerfile")
        assert artifact.metadata["from_image"] == "python:3.12-slim"

    def test_extracts_user(self):
        content = "FROM ubuntu\nUSER appuser\n"
        artifact = self.parser.parse(content, "Dockerfile")
        assert artifact.metadata["user"] == "appuser"

    def test_extracts_exposed_ports(self):
        content = "FROM nginx\nEXPOSE 80 443\n"
        artifact = self.parser.parse(content, "Dockerfile")
        assert "80" in artifact.metadata["exposed_ports"]
        assert "443" in artifact.metadata["exposed_ports"]

    def test_detects_healthcheck(self):
        content = "FROM python\nHEALTHCHECK CMD curl -f http://localhost || exit 1\n"
        artifact = self.parser.parse(content, "Dockerfile")
        assert artifact.metadata["has_healthcheck"] is True

    def test_ignores_comments(self):
        content = "# This is a comment\nFROM alpine\n# another comment\nRUN echo hi\n"
        artifact = self.parser.parse(content, "Dockerfile")
        assert len(artifact.raw["instructions"]) == 2


class TestHelmParser:
    def setup_method(self):
        self.parser = HelmParser()

    def test_supports_template_files(self):
        assert self.parser.supports("templates/deployment.yaml") is True
        assert self.parser.supports("deploy.yaml") is False

    def test_extracts_template_variables(self):
        content = """
apiVersion: v1
kind: Service
metadata:
  name: "{{ .Values.service.name }}"
spec:
  ports:
    - port: "{{ .Values.service.port }}"
"""
        artifact = self.parser.parse(content, "templates/service.yaml")
        assert "service.name" in artifact.metadata["template_variables"]
        assert "service.port" in artifact.metadata["template_variables"]

    def test_no_variables_in_static_template(self):
        content = """
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
"""
        artifact = self.parser.parse(content, "templates/config.yaml")
        assert artifact.metadata["has_template_expressions"] is False
