package rules

import (
	"path"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// maxShellDepth bounds the re-parsing of nested scripts (bash -c, eval).
const maxShellDepth = 8

// wrapperCommands run another command given in their arguments. Their option
// syntax differs per command, so instead of modelling each one, every suffix
// of the argument list is treated as a possible command. This errs on the
// side of matching too much.
var wrapperCommands = map[string]bool{
	"builtin": true, "chronic": true, "command": true, "doas": true,
	"env": true, "exec": true, "ionice": true, "nice": true, "nohup": true,
	"setsid": true, "stdbuf": true, "sudo": true, "time": true,
	"timeout": true, "unbuffer": true, "watch": true, "xargs": true,
}

// shellCommands take a script as the argument of -c.
var shellCommands = map[string]bool{
	"ash": true, "bash": true, "dash": true, "ksh": true, "sh": true, "zsh": true,
}

// commandUnits splits a shell command line into the simple commands it would
// execute. Each unit is "name arg arg..." with quoting removed, so a rule
// anchored with ^ matches the head of each command rather than the head of
// the line.
//
// Text that is only data is not part of any unit head: heredoc bodies are
// dropped, and quoted strings appear only as arguments of the command that
// receives them. Data that becomes a command is parsed again: bash -c, eval,
// find -exec and the wrappers in wrapperCommands.
//
// ok is false when the line cannot be resolved statically (a syntax error, a
// command name built from an expansion, nesting that is too deep). The caller
// must then also match against the raw string.
func commandUnits(cmd string) (units []string, ok bool) {
	c := &unitCollector{ok: true}
	c.parse(cmd, 0)
	return c.units, c.ok
}

type unitCollector struct {
	units []string
	ok    bool
}

func (c *unitCollector) parse(src string, depth int) {
	if depth > maxShellDepth {
		c.ok = false
		return
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		c.ok = false
		return
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		argv := make([]string, len(call.Args))
		for i, w := range call.Args {
			text, static := wordText(w)
			if !static && i == 0 {
				// The command itself is decided at run time.
				c.ok = false
			}
			argv[i] = text
		}
		c.command(argv, depth, true)
		return true // descend into $(...) inside the arguments
	})
}

// command records one simple command and follows the arguments that are
// themselves commands.
func (c *unitCollector) command(argv []string, depth int, expandWrappers bool) {
	if len(argv) == 0 {
		return
	}
	name := path.Base(argv[0])
	c.units = append(c.units, strings.Join(argv, " "))
	if name != argv[0] {
		// /usr/bin/git push must match rules written for "git push".
		c.units = append(c.units, strings.Join(append([]string{name}, argv[1:]...), " "))
	}

	switch {
	case shellCommands[name]:
		if script, found := shellScriptArg(argv[1:]); found {
			c.parse(script, depth+1)
		}
	case name == "eval":
		c.parse(strings.Join(argv[1:], " "), depth+1)
	case name == "find":
		for i, a := range argv {
			switch a {
			case "-exec", "-execdir", "-ok", "-okdir":
				end := i + 1
				for end < len(argv) && argv[end] != ";" && argv[end] != "+" {
					end++
				}
				c.command(argv[i+1:end], depth, true)
			}
		}
	case wrapperCommands[name] && expandWrappers:
		for i := 1; i < len(argv); i++ {
			c.command(argv[i:], depth, false)
		}
	}
}

// shellScriptArg returns the script passed to a shell with -c. Options may be
// clustered (-lc, -ec); the script is the first non-option argument after it.
func shellScriptArg(args []string) (string, bool) {
	seenC := false
	for _, a := range args {
		if a == "--" {
			continue
		}
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "--") {
			if strings.Contains(a, "c") {
				seenC = true
			}
			continue
		}
		if strings.HasPrefix(a, "--") {
			continue
		}
		if seenC {
			return a, true
		}
		return "", false // a script file, not -c
	}
	return "", false
}

// wordText returns the value of a word after quote removal. static is false
// when the word contains an expansion; the text is then its source form.
func wordText(w *syntax.Word) (text string, static bool) {
	var sb strings.Builder
	if appendParts(&sb, w.Parts, false) {
		return sb.String(), true
	}
	sb.Reset()
	syntax.NewPrinter().Print(&sb, w)
	return sb.String(), false
}

func appendParts(sb *strings.Builder, parts []syntax.WordPart, quoted bool) bool {
	for _, p := range parts {
		switch p := p.(type) {
		case *syntax.Lit:
			sb.WriteString(unescapeLit(p.Value, quoted))
		case *syntax.SglQuoted:
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			if !appendParts(sb, p.Parts, true) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// unescapeLit removes the backslashes that the shell would remove.
func unescapeLit(s string, quoted bool) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			sb.WriteByte(s[i])
			continue
		}
		next := s[i+1]
		if next == '\n' {
			i++ // line continuation
			continue
		}
		if quoted && !strings.ContainsRune("$`\"\\", rune(next)) {
			sb.WriteByte(s[i]) // inside "...", the backslash stays
			continue
		}
		sb.WriteByte(next)
		i++
	}
	return sb.String()
}
