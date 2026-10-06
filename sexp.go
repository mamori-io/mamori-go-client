package mamori

import (
	"errors"
	"regexp"
	"strconv"
)

var sexpNumber = regexp.MustCompile(`^-?\d+(?:\.\d+)?$`)

// Symbol is an unquoted atom in a parsed s-expression.
type Symbol string

// ParseSexp parses a single s-expression list such as `(a "b" (1 2.5))`.
// Lists become []any, quoted strings string, numbers float64 and other atoms
// [Symbol]. String contents are returned verbatim (escapes are not
// interpreted), matching the TypeScript SDK.
func ParseSexp(src string) ([]any, error) {
	p := sexpParser{src: src}
	return p.list()
}

type sexpParser struct {
	src string
	i   int
}

var errSexp = errors.New("mamori: s-expression parse error")

func isSexpSpace(c byte) bool { return c == ' ' || c == '\r' || c == '\n' || c == '\t' }

func isSexpAtom(c byte) bool {
	return c != '(' && c != ')' && c != '\'' && c != '"' && !isSexpSpace(c)
}

func (p *sexpParser) list() ([]any, error) {
	for p.i < len(p.src) && isSexpSpace(p.src[p.i]) {
		p.i++
	}
	if p.i >= len(p.src) || p.src[p.i] != '(' {
		return nil, errSexp
	}
	p.i++
	items := []any{}
	for p.i < len(p.src) {
		switch c := p.src[p.i]; {
		case c == ')':
			p.i++
			return items, nil
		case c == '(':
			sub, err := p.list()
			if err != nil {
				return nil, err
			}
			items = append(items, sub)
		case c == '"' || c == '\'':
			s, err := p.str(c)
			if err != nil {
				return nil, err
			}
			items = append(items, s)
		case isSexpSpace(c):
			p.i++
		default:
			items = append(items, p.atom())
		}
	}
	return nil, errSexp
}

func (p *sexpParser) atom() any {
	start := p.i
	p.i++
	for p.i < len(p.src) && isSexpAtom(p.src[p.i]) {
		p.i++
	}
	a := p.src[start:p.i]
	if sexpNumber.MatchString(a) {
		if f, err := strconv.ParseFloat(a, 64); err == nil {
			return f
		}
	}
	return Symbol(a)
}

func (p *sexpParser) str(quote byte) (string, error) {
	start := p.i
	p.i++
	for p.i < len(p.src) && p.src[p.i] != quote {
		if p.src[p.i] == '\\' {
			p.i++
		}
		p.i++
	}
	if p.i >= len(p.src) {
		return "", errors.New("mamori: s-expression parse error: unterminated string")
	}
	p.i++
	return p.src[start+1 : p.i-1], nil
}
