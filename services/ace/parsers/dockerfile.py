import re

from .base import BaseParser, NormalizedArtifact


class DockerfileParser(BaseParser):
    def supports(self, filename: str) -> bool:
        return filename == "Dockerfile" or filename.endswith(".dockerfile")

    def parse(self, content: str, name: str) -> NormalizedArtifact:
        instructions = self._parse_instructions(content)
        return NormalizedArtifact(
            artifact_type="dockerfile",
            name=name,
            raw={"instructions": instructions},
            metadata={
                "from_image": self._extract_from_image(instructions),
                "user": self._extract_user(instructions),
                "has_healthcheck": any(i["instruction"] == "HEALTHCHECK" for i in instructions),
                "has_entrypoint": any(i["instruction"] in ("ENTRYPOINT", "CMD") for i in instructions),
                "exposed_ports": self._extract_ports(instructions),
            }
        )

    def _parse_instructions(self, content: str) -> list[dict]:
        instructions = []
        for line in content.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 1)
            instr = parts[0].upper()
            args = parts[1] if len(parts) > 1 else ""
            instructions.append({"instruction": instr, "args": args})
        return instructions

    def _extract_from_image(self, instructions: list[dict]) -> str:
        for i in instructions:
            if i["instruction"] == "FROM":
                return i["args"]
        return ""

    def _extract_user(self, instructions: list[dict]) -> str:
        for i in instructions:
            if i["instruction"] == "USER":
                return i["args"]
        return ""

    def _extract_ports(self, instructions: list[dict]) -> list[str]:
        ports = []
        for i in instructions:
            if i["instruction"] == "EXPOSE":
                ports.extend(re.findall(r'\d+', i["args"]))
        return ports
