import ast

class GreenCodeAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.loops = 0
        self.nested_loops = 0
        self.conditionals = 0
        self.function_calls = 0
        self.max_loop_depth = 0
        self.current_loop_depth = 0

    def visit_For(self, node):
        self.loops += 1
        self.current_loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.current_loop_depth)
        self.generic_visit(node)
        self.current_loop_depth -= 1

    def visit_While(self, node):
        self.loops += 1
        self.current_loop_depth += 1
        self.max_loop_depth = max(self.max_loop_depth, self.current_loop_depth)
        self.generic_visit(node)
        self.current_loop_depth -= 1

    def visit_If(self, node):
        self.conditionals += 1
        self.generic_visit(node)

    def visit_Call(self, node):
        self.function_calls += 1
        self.generic_visit(node)

    def analyze(self, code):
        tree = ast.parse(code)
        self.visit(tree)
        # Simple energy score calculation
        energy_score = (
            self.loops * 2 +
            self.max_loop_depth * 3 +
            self.function_calls * 1 +
            self.conditionals * 0.5
        )
        suggestions = []

        if self.max_loop_depth > 2:
            suggestions.append("Consider reducing nested loops or use vectorized operations.")
        if self.function_calls > 10:
            suggestions.append("Check for repeated function calls; caching results may help.")
        if self.loops > 10:
            suggestions.append("Loops are high; consider optimizing iterations.")

        return {
            "loops": self.loops,
            "nested_loops": self.max_loop_depth,
            "function_calls": self.function_calls,
            "conditionals": self.conditionals,
            "energy_score": energy_score,
            "suggestions": suggestions
        }


if __name__ == "__main__":
    # Example usage
    code_file = input("Enter path to Python file: ")
    with open(code_file, "r") as f:
        code = f.read()

    analyzer = GreenCodeAnalyzer()
    result = analyzer.analyze(code)

    print("\n--- Green Code Analysis ---")
    print(f"Loops: {result['loops']}")
    print(f"Nested loops (max depth): {result['nested_loops']}")
    print(f"Function calls: {result['function_calls']}")
    print(f"Conditionals: {result['conditionals']}")
    print(f"Energy Score: {result['energy_score']}")
    print("Suggestions:")
    for s in result['suggestions']:
        print(f"- {s}")
