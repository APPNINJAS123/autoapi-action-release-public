// This helper parses customer source; it never imports or executes it.
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strconv"
	"strings"
)

type input struct {
	Content         string            `json:"content"`
	Modules         []string          `json:"modules"`
	DefaultPackages map[string]string `json:"defaultPackages"`
}
type usage struct {
	Module      string `json:"module"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	Declaration string `json:"declaration"`
}

func main() {
	var request input
	if json.NewDecoder(io.LimitReader(os.Stdin, 3*1024*1024)).Decode(&request) != nil {
		os.Exit(2)
	}
	if len(request.Content) > 2*1024*1024 || len(request.Modules) > 100 {
		os.Exit(2)
	}
	fset := token.NewFileSet()
	// Object resolution is deliberately enabled: shadowed identifiers have Obj
	// bindings, unlike references to imported package qualifiers.
	file, err := parser.ParseFile(fset, "customer.go", request.Content, parser.AllErrors)
	if err != nil {
		os.Exit(2)
	}
	aliases := map[string]string{}
	seenAliases := map[string]bool{}
	for _, spec := range file.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			os.Exit(2)
		}
		alias := request.DefaultPackages[importPath]
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias != "" && alias != "_" && alias != "." {
			if seenAliases[alias] {
				os.Exit(2)
			}
			seenAliases[alias] = true
		}
		module := ""
		for _, candidate := range request.Modules {
			if importPath == candidate || strings.HasPrefix(importPath, candidate+"/") {
				if module != "" && module != candidate {
					os.Exit(2)
				}
				module = candidate
			}
		}
		if module == "" {
			continue
		}
		if alias == "" || alias == "_" || alias == "." {
			continue
		}
		if _, duplicate := aliases[alias]; duplicate {
			os.Exit(2)
		}
		aliases[alias] = module
	}
	usages := []usage{}
	for _, declaration := range file.Decls {
		name := ""
		switch node := declaration.(type) {
		case *ast.FuncDecl:
			name = node.Name.Name
		case *ast.GenDecl:
			if node.Tok == token.IMPORT {
				continue
			}
			name = node.Tok.String()
		default:
			continue
		}
		matched := map[string]bool{}
		ast.Inspect(declaration, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok || identifier.Obj != nil {
				return true
			}
			if module := aliases[identifier.Name]; module != "" {
				matched[module] = true
			}
			return true
		})
		start, end := fset.Position(declaration.Pos()).Line, fset.Position(declaration.End()).Line
		if end-start > 1000 {
			continue
		}
		for _, module := range request.Modules {
			if matched[module] {
				usages = append(usages, usage{module, start, end, name})
			}
		}
		if len(usages) > 2000 {
			os.Exit(2)
		}
	}
	if json.NewEncoder(os.Stdout).Encode(usages) != nil {
		os.Exit(2)
	}
}
