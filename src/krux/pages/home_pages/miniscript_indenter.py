# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


class Node:
    """
    A simple tree node that only stores:
      - text: The 'prefix' of the expression before an open parenthesis,
              or the entire expression if no parentheses exist.
      - children: Any sub-expressions contained within parentheses (split by commas at top level).
      - level: An integer used to control indentation depth.
    """

    def __init__(self, text, children=None, level=0):
        self.text = text
        self.children = children if children is not None else []
        self.level = level


class MiniScriptIndenter:
    """
    Indent MiniScript expressions.
    """

    def indent(self, expression, max_line_width=25):
        """
        Indent a MiniScript expression, breaking lines as needed to fit within max_line_width.
        """
        tree = self._parse_expression(expression)
        indented_lines = self._node_to_indented_string(tree, max_line_width)
        final_lines = []
        for line in indented_lines:
            final_lines.extend(self._break_lines(line, max_line_width))
        return final_lines

    def _split_top_level_args(self, s, delimiter=","):
        """
        Splits string s by the top-level delimiter (by default a comma).
        """
        parts = []
        bracket_level = 0
        current = []
        for ch in s:
            if ch == "(":
                bracket_level += 1
                current.append(ch)
            elif ch == ")":
                bracket_level -= 1
                current.append(ch)
            elif ch == delimiter and bracket_level == 0:
                parts.append("".join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            parts.append("".join(current).strip())
        return parts

    def _parse_expression(self, expr, level=0):
        """
        Recursively parse the expression into a Node that reflects parentheses structure.

        Steps:
        - If there's no parenthesis at all, this is a leaf node.
        - Otherwise:
            prefix: the text before '('
            inside: the substring inside the outermost parentheses
            children: sub-expressions inside 'inside', separated at top-level commas
        """
        expr = expr.strip()
        pos = expr.find("(")
        if pos == -1:
            # No '(' => leaf node
            return Node(text=expr, children=[], level=level)

        prefix = expr[:pos].strip()
        inside = expr[pos + 1 : -1].strip()
        sub_expressions = self._split_top_level_args(inside)
        children = [
            self._parse_expression(sub_expr, level=level + 1)
            for sub_expr in sub_expressions
        ]

        return Node(text=prefix, children=children, level=level)

    def _join_closing_parens(self, lines):
        """
        Post-processing step:
        If a line is only one or more closing parentheses (possibly with indentation),
        append them to the end of the previous line, so no line is just ')'.

        """
        i = len(lines) - 1
        while i > 0:
            stripped = lines[i].strip()
            # Check if stripped is only some number of ')'
            if stripped and all(ch == ")" for ch in stripped):
                # Append them (minus indentation) to previous line
                lines[i - 1] = "{0}{1}".format(lines[i - 1], stripped)
                lines.pop(i)
            i -= 1
        return lines

    def _node_to_indented_string(self, node, max_line_width=25):
        """
        Convert the Node tree into an indented list of strings with two rules:
        1) If any child is a leaf, flatten all children into a single line with the parent.
        2) Remove lines that only contain ')', by merging them into the previous line.
        3) Ensure no line exceeds max_line_width by breaking long lines.
        """

        # If no children => leaf node
        if not node.children:
            indent = " " * node.level
            return ["{0}{1}".format(indent, node.text)]

        # If any child is a leaf, flatten them all
        # It's likely it will group multi and thresh children together
        any_child_is_leaf = any(not c.children for c in node.children)
        if any_child_is_leaf and node.level > 0:
            # Flatten children on one line
            indent = " " * node.level
            line = "{0}{1}(".format(indent, node.text)
            child_texts = []
            for child in node.children:
                child_str = self._node_to_indented_string(child, max_line_width)
                # # compress any newlines to single space
                # child_str = child_str.replace("\n", " ")
                child_texts.append(child_str[0].strip())
            line += ",".join(child_texts) + ")"
            # If flattened line is short enough, return it
            if len(line) <= max_line_width:
                return [line]
            # Else break it into multiple lines as if here was no leaf children

        # Multi-line approach
        indent = " " * node.level
        lines = []
        lines.append("{0}{1}(".format(indent, node.text))
        for i, child in enumerate(node.children):
            child_lines = self._node_to_indented_string(child, max_line_width)
            # If not the last child, add a trailing comma
            if i < len(node.children) - 1:
                child_lines[-1] = "{0},".format(child_lines[-1])
            lines.extend(child_lines)
        lines.append("{0})".format(indent))

        # Post-process lines to join any lines that are just ')'
        lines = self._join_closing_parens(lines)

        return lines

    def _break_lines(self, line, max_line_width):
        """
        Break a line into multiple lines if it exceeds max_line_width.
        """
        if len(line) <= max_line_width:
            return [line]
        indent = 0
        while True:
            if line[indent] != " ":
                break
            indent += 1
        data = line[indent:]
        parts = []
        while len(data) > max_line_width - indent:
            parts.append(" " * indent + data[: max_line_width - indent])
            data = data[max_line_width - indent :]
        parts.append(" " * indent + data)
        return parts
