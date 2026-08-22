"""Robust zero-dependency static YAML parser for IaC files."""

import json
import re
from typing import Any, Dict, List, Union

try:
    import yaml
    HAS_PYYAML = True
except ImportError:
    HAS_PYYAML = False


def safe_yaml_load(content: str) -> Any:
    """Parses standard key-value, nested dictionary, and list structures in YAML line by line."""
    if HAS_PYYAML:
        try:
            res = yaml.safe_load(content)
            if res is not None:
                return res
        except Exception:
            pass

    lines = content.splitlines()
    non_empty = [l for l in lines if l.strip() and not l.strip().startswith("#")]
    if not non_empty:
        return {}

    min_indent = min(len(l) - len(l.lstrip()) for l in non_empty)
    if min_indent > 0:
        lines = [l[min_indent:] if len(l) >= min_indent and l[:min_indent].isspace() else l for l in lines]

    root: Dict[str, Any] = {}
    # stack: list of [indent, container, container_type, parent_dict, key_in_parent]
    stack: List[List[Any]] = [[-1, root, "dict", None, None]]

    for line in lines:
        raw_stripped = line.rstrip()
        if not raw_stripped or raw_stripped.lstrip().startswith("#"):
            continue

        indent = len(raw_stripped) - len(raw_stripped.lstrip())
        clean = raw_stripped.strip()

        # Pop stack levels when indentation decreases or stays equal (except list item bullet under list)
        while len(stack) > 1:
            top_indent, top_container, top_type, p_dict, p_key = stack[-1]
            if clean.startswith("- ") and top_type == "list" and indent == top_indent:
                break
            if indent <= top_indent:
                stack.pop()
            else:
                break

        parent_indent, parent_container, parent_type, p_dict, p_key = stack[-1]

        if clean.startswith("- "):
            val_str = clean[2:].strip()

            if parent_type == "dict":
                # Convert the empty dict placeholder at p_key in p_dict to a list if parent_container is empty
                if isinstance(p_dict, dict) and p_key is not None and parent_container == {}:
                    target_list: List[Any] = []
                    p_dict[p_key] = target_list
                    # Update current stack top to represent the list container
                    stack[-1] = [indent, target_list, "list", p_dict, p_key]
                else:
                    key = list(parent_container.keys())[-1] if parent_container else None
                    if key:
                        if not isinstance(parent_container.get(key), list):
                            parent_container[key] = []
                        target_list = parent_container[key]
                        stack.append([indent, target_list, "list", parent_container, key])
                    else:
                        target_list = []
            elif parent_type == "list":
                target_list = parent_container
            else:
                target_list = []

            val_unquoted = val_str.strip("\"'")
            is_quoted = (val_str.startswith('"') and val_str.endswith('"')) or (val_str.startswith("'") and val_str.endswith("'"))
            
            if ":" in val_unquoted and not is_quoted and "${{" not in val_unquoted:
                parts = val_unquoted.split(":", 1)
                k, v = parts[0].strip(), parts[1].strip()
                if (k.replace(".", "").replace(":", "").isdigit() or 
                    re.match(r"^\d+\.\d+\.\d+\.\d+", val_unquoted) or 
                    re.match(r"^\d+:\d+", val_unquoted)):
                    target_list.append(_parse_val(val_str))
                else:
                    item_dict = {k: _parse_val(v)} if v else {}
                    target_list.append(item_dict)
                    stack.append([indent, item_dict, "dict", target_list, len(target_list) - 1])
            else:
                target_list.append(_parse_val(val_str))

        elif ":" in clean:
            parts = clean.split(":", 1)
            k = parts[0].strip().strip("\"'")
            v = parts[1].strip() if len(parts) > 1 else ""

            if parent_type == "dict":
                if not v:
                    new_dict: Dict[str, Any] = {}
                    parent_container[k] = new_dict
                    stack.append([indent, new_dict, "dict", parent_container, k])
                else:
                    parent_container[k] = _parse_val(v)

    return root


def safe_yaml_load_all(content: str) -> List[Any]:
    """Parses multi-document YAML strings (separated by ---)."""
    if HAS_PYYAML:
        try:
            res = list(yaml.safe_load_all(content))
            if res:
                return [r for r in res if r is not None]
        except Exception:
            pass

    docs_raw = re.split(r"^\s*---\s*$", content, flags=re.MULTILINE)
    results = []
    for doc_str in docs_raw:
        doc_clean = doc_str.strip()
        if doc_clean:
            res = safe_yaml_load(doc_clean)
            if res:
                results.append(res)
    return results


def _parse_val(val: str) -> Any:
    if not val:
        return None
    val_clean = val.strip("\"'")
    if val_clean.startswith("[") and val_clean.endswith("]"):
        items = val_clean[1:-1].split(",")
        return [_parse_val(it.strip()) for it in items if it.strip()]
    if val_clean.lower() == "true":
        return True
    if val_clean.lower() == "false":
        return False
    try:
        if "." in val_clean:
            return float(val_clean)
        return int(val_clean)
    except ValueError:
        return val_clean
