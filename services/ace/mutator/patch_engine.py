import copy
from typing import Any


class PatchEngine:
    MAX_RETRIES = 3

    @staticmethod
    def apply_patches(artifact: dict, patches: list[dict]) -> tuple[dict, list[str]]:
        patched = copy.deepcopy(artifact)
        applied = []

        for patch in patches:
            op = patch["op"]
            path = patch["path"]
            value = patch.get("value")
            keys = [k for k in path.strip("/").split("/") if k]

            try:
                if op == "replace":
                    PatchEngine._set_nested(patched, keys, value)
                    applied.append(f"replace {path} -> {value}")
                elif op == "add":
                    PatchEngine._set_nested(patched, keys, value)
                    applied.append(f"add {path} = {value}")
                elif op == "remove":
                    PatchEngine._remove_nested(patched, keys)
                    applied.append(f"remove {path}")
            except (KeyError, IndexError, TypeError):
                PatchEngine._create_path(patched, keys, value)
                applied.append(f"create+set {path} = {value}")

        return patched, applied

    @staticmethod
    def diff(before: dict, after: dict) -> list[dict]:
        changes = []
        PatchEngine._diff_recursive(before, after, "", changes)
        return changes

    @staticmethod
    def _set_nested(obj: Any, keys: list[str], value: Any) -> None:
        for key in keys[:-1]:
            if isinstance(obj, list):
                obj = obj[int(key)]
            else:
                obj = obj[key]
        final_key = keys[-1]
        if isinstance(obj, list):
            obj[int(final_key)] = value
        else:
            obj[final_key] = value

    @staticmethod
    def _remove_nested(obj: Any, keys: list[str]) -> None:
        for key in keys[:-1]:
            obj = obj[int(key)] if isinstance(obj, list) else obj[key]
        final = keys[-1]
        if isinstance(obj, list):
            del obj[int(final)]
        else:
            del obj[final]

    @staticmethod
    def _create_path(obj: dict, keys: list[str], value: Any) -> None:
        for i, key in enumerate(keys[:-1]):
            next_key = keys[i + 1]
            is_next_numeric = next_key.lstrip('-').isdigit()
            if isinstance(obj, list):
                idx = int(key)
                while len(obj) <= idx:
                    obj.append([] if is_next_numeric else {})
                obj = obj[idx]
            elif is_next_numeric:
                obj = obj.setdefault(key, [])
            else:
                obj = obj.setdefault(key, {})
        final = keys[-1]
        if isinstance(obj, dict):
            obj[final] = value
        elif isinstance(obj, list):
            idx = int(final)
            while len(obj) <= idx:
                obj.append(None)
            obj[idx] = value

    @staticmethod
    def _diff_recursive(before: Any, after: Any, path: str, changes: list) -> None:
        if isinstance(before, dict) and isinstance(after, dict):
            for key in set(list(before.keys()) + list(after.keys())):
                new_path = f"{path}/{key}"
                if key not in before:
                    changes.append({"op": "add", "path": new_path, "value": after[key]})
                elif key not in after:
                    changes.append({"op": "remove", "path": new_path})
                else:
                    PatchEngine._diff_recursive(before[key], after[key], new_path, changes)
        elif before != after:
            changes.append({"op": "replace", "path": path, "before": before, "after": after})
