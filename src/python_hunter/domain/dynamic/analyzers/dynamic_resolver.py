"""Static Dynamic Resolver for Constant Propagation and Value Set Inference."""

import ast
from typing import Any


class DynamicResolver:
    """Statically resolves local variable constants, string literals, and collection value sets."""

    def __init__(self, max_set_size: int = 10, max_depth: int = 5) -> None:
        self.max_set_size = max_set_size
        self.max_depth = max_depth

    def resolve_expression(self, node: ast.AST, env: dict[str, set[Any]] | None = None, depth: int = 0) -> set[Any]:
        """Statically evaluate possible constant values for an AST expression."""
        if node is None or depth > self.max_depth:
            return set()

        env = env or {}

        # 1. Constant literal
        if isinstance(node, ast.Constant):
            return {node.value}
        elif isinstance(node, ast.Str):
            return {node.s}
        elif isinstance(node, ast.Num):
            return {node.n}

        # 2. Variable lookup
        elif isinstance(node, ast.Name):
            if node.id in env:
                return env[node.id]

        # 3. String concatenation / BinOp
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left_vals = self.resolve_expression(node.left, env, depth + 1)
            right_vals = self.resolve_expression(node.right, env, depth + 1)
            res = set()
            for l in left_vals:
                for r in right_vals:
                    if isinstance(l, str) and isinstance(r, str):
                        res.add(l + r)
                    elif isinstance(l, (int, float)) and isinstance(r, (int, float)):
                        res.add(l + r)
                    if len(res) >= self.max_set_size:
                        break
                if len(res) >= self.max_set_size:
                    break
            return res

        # 4. F-String / JoinedStr
        elif isinstance(node, ast.JoinedStr):
            parts_sets = []
            for val in node.values:
                if isinstance(val, ast.Constant) and isinstance(val.value, str):
                    parts_sets.append({val.value})
                elif isinstance(val, ast.FormattedValue):
                    sub_vals = self.resolve_expression(val.value, env, depth + 1)
                    parts_sets.append({str(v) for v in sub_vals} if sub_vals else {"<dynamic>"})
                else:
                    parts_sets.append({"<dynamic>"})
            
            # Cartesian product of parts
            results = {""}
            for pset in parts_sets:
                next_res = set()
                for base in results:
                    for part in pset:
                        next_res.add(base + part)
                        if len(next_res) >= self.max_set_size:
                            break
                    if len(next_res) >= self.max_set_size:
                        break
                results = next_res
            return results

        # 5. List / Tuple / Set literals
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            elems = set()
            for elt in node.elts:
                sub = self.resolve_expression(elt, env, depth + 1)
                elems.update(sub)
                if len(elems) >= self.max_set_size:
                    break
            return elems

        # 6. Dict literal keys/values
        elif isinstance(node, ast.Dict):
            keys = set()
            for k in node.keys:
                if k is not None:
                    keys.update(self.resolve_expression(k, env, depth + 1))
            return keys

        return set()

    def build_local_env(self, tree: ast.AST) -> dict[str, set[Any]]:
        """Walk AST and collect variable constant assignments."""
        env: dict[str, set[Any]] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                vals = self.resolve_expression(node.value, env)
                if vals and len(vals) <= self.max_set_size:
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            env[target.id] = vals
        return env
