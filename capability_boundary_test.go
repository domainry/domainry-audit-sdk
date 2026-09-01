package auditsdk_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestSDKCapabilityBoundaryDoesNotDependOnPlaneOrRuntime(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve SDK repository root")
	}
	root := filepath.Dir(source)
	forbidden := []string{"github.com/domainry/domainry-plane", "github.com/domainry/domainry-runtime"}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "dist" || entry.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, declaration := range parsed.Imports {
			importPath, err := strconv.Unquote(declaration.Path.Value)
			if err != nil {
				return err
			}
			for _, prefix := range forbidden {
				if importPath == prefix || strings.HasPrefix(importPath, prefix+"/") {
					t.Errorf("SDK file %s imports forbidden implementation package %s", path, importPath)
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
