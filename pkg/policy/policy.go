package policy

import (
	"fmt"
	"strings"
)

// Policy represents a parsed boolean expression referencing match controller
// names. The AST is intentionally simple to keep evaluation predictable and fast.
type Policy struct {
	root node
}

// Parse builds a policy AST ensuring every identifier exists in the provided name set.
// Empty expressions evaluate to an implicit "allow all" and thus return a nil policy.
func Parse(expr string, controllerNames []string) (*Policy, error) {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return nil, nil
	}

	parserNames := make(map[string]struct{})
	for _, controllerName := range controllerNames {
		parserNames[controllerName] = struct{}{}
	}

	p := &parser{input: trimmed, names: parserNames}
	root, err := p.parseExpression()
	if err != nil {
		return nil, err
	}
	p.skipWhitespace()
	if !p.eof() {
		return nil, fmt.Errorf("unexpected token at position %d", p.pos+1)
	}
	return &Policy{root: root}, nil
}

// Evaluate executes the compiled policy using the boolean assignments passed in. The
// method returns the resulting truthiness plus the controller name that caused a false
// result (if known) so the caller can log or report the culprit.
func (p *Policy) Evaluate(values map[string]bool) (bool, string) {
	if p == nil || p.root == nil {
		return true, ""
	}
	allowed, cause := p.root.eval(values)
	return allowed, cause
}

// node abstracts AST nodes so each implementation can perform evaluation independently.
type node interface {
	eval(values map[string]bool) (bool, string)
}

// identifierNode represents a single controller name.
type identifierNode struct {
	name string
}

// notNode implements logical negation of its child node.
type notNode struct {
	child node
}

// binaryNode represents both logical AND and OR expressions.
type binaryNode struct {
	op    string
	left  node
	right node
}

// eval returns the truth value for the controller and the controller name itself.
func (n *identifierNode) eval(values map[string]bool) (bool, string) {
	val := values[n.name]
	return val, n.name
}

// eval inverts the child's truthiness but preserves the original controller name so the
// calling code can track which controller triggered the policy decision.
func (n *notNode) eval(values map[string]bool) (bool, string) {
	val, cause := n.child.eval(values)
	return !val, cause
}

// eval evaluates both operands according to the stored operator and short-circuits
// whenever possible. The offending controller name is propagated so callers can report it.
func (n *binaryNode) eval(values map[string]bool) (bool, string) {
	switch n.op {
	case "&&":
		leftVal, leftCause := n.left.eval(values)
		if !leftVal {
			return false, leftCause
		}
		rightVal, rightCause := n.right.eval(values)
		if !rightVal {
			return false, rightCause
		}
		return true, ""
	case "||":
		leftVal, _ := n.left.eval(values)
		if leftVal {
			return true, ""
		}
		rightVal, rightCause := n.right.eval(values)
		if rightVal {
			return true, ""
		}
		return false, rightCause
	default:
		return false, ""
	}
}

// parser holds state for a single pass over the policy expression string.
type parser struct {
	input string
	pos   int
	names map[string]struct{}
}

// parseExpression kicks off recursive descent parsing; the grammar entry point matches
// OR expressions which in turn reduce to ANDs and unary expressions.
func (p *parser) parseExpression() (node, error) {
	return p.parseOr()
}

// parseOr handles the lowest-precedence operator (||) by repeatedly consuming AND
// expressions until the operator no longer matches.
func (p *parser) parseOr() (node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWhitespace()
		if strings.HasPrefix(p.remaining(), "||") {
			p.pos += 2
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			left = &binaryNode{op: "||", left: left, right: right}
			continue
		}
		break
	}
	return left, nil
}

// parseAnd handles chained && operators and delegates operand parsing to parseUnary.
func (p *parser) parseAnd() (node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		p.skipWhitespace()
		if strings.HasPrefix(p.remaining(), "&&") {
			p.pos += 2
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = &binaryNode{op: "&&", left: left, right: right}
			continue
		}
		break
	}
	return left, nil
}

// parseUnary recognizes optional logical NOT sequences before falling back to primaries.
func (p *parser) parseUnary() (node, error) {
	p.skipWhitespace()
	if p.match('!') {
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &notNode{child: child}, nil
	}
	return p.parsePrimary()
}

// parsePrimary returns grouped expressions (parentheses) or controller identifiers.
func (p *parser) parsePrimary() (node, error) {
	p.skipWhitespace()
	if p.match('(') {
		// Nested expressions allow parentheses to override precedence.
		expr, err := p.parseExpression()
		if err != nil {
			return nil, err
		}
		p.skipWhitespace()
		if !p.match(')') {
			return nil, fmt.Errorf("expected ) at position %d", p.pos+1)
		}
		return expr, nil
	}

	ident := p.readIdentifier()
	if ident == "" {
		return nil, fmt.Errorf("expected identifier at position %d", p.pos+1)
	}
	if len(p.names) > 0 {
		if _, ok := p.names[ident]; !ok {
			return nil, fmt.Errorf("authorization policy references an unknown controller: %s", ident)
		}
	}
	return &identifierNode{name: ident}, nil
}

// skipWhitespace advances the parser cursor past any whitespace characters.
func (p *parser) skipWhitespace() {
	for !p.eof() && isWhitespace(p.peek()) {
		p.pos++
	}
}

// remaining returns the unparsed tail of the expression.
func (p *parser) remaining() string {
	if p.pos >= len(p.input) {
		return ""
	}
	return p.input[p.pos:]
}

// eof indicates whether the cursor has consumed the entire input.
func (p *parser) eof() bool {
	return p.pos >= len(p.input)
}

// peek returns the current byte without advancing the cursor.
func (p *parser) peek() byte {
	if p.eof() {
		return 0
	}
	return p.input[p.pos]
}

// match consumes the next byte if it matches the expected token.
func (p *parser) match(ch byte) bool {
	if p.eof() || p.input[p.pos] != ch {
		return false
	}
	p.pos++
	return true
}

// readIdentifier scans consecutive identifier characters (letters, numbers, dashes,
// underscores, or dots) into a token.
func (p *parser) readIdentifier() string {
	start := p.pos
	for !p.eof() {
		r := p.input[p.pos]
		if isIdentChar(r) {
			p.pos++
			continue
		}
		break
	}
	return p.input[start:p.pos]
}

// isWhitespace reports whether the byte is considered whitespace by the parser.
func isWhitespace(b byte) bool {
	return b == ' ' || b == '\n' || b == '\t' || b == '\r'
}

// isIdentChar reports whether the byte is allowed inside an identifier.
func isIdentChar(b byte) bool {
	if b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' {
		return true
	}
	switch b {
	case '-', '_', '.':
		return true
	default:
		return false
	}
}
