package security

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func SafeJoin(root, userPath string) (string, error) {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	cleanRel := filepath.Clean(userPath)
	cleanRel = strings.TrimLeft(cleanRel, string(os.PathSeparator))
	if cleanRel == "." {
		cleanRel = ""
	}
	candidate := filepath.Join(cleanRoot, cleanRel)
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(candidate, cleanRoot+string(os.PathSeparator)) && candidate != cleanRoot {
		return "", errors.New("path escapes root")
	}
	return candidate, nil
}

func CheckSymlinkEscape(root, path string) error {
	cleanRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	evaluated, err := filepath.EvalSymlinks(path)
	if err == nil {
		evaluated, err = filepath.Abs(evaluated)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(evaluated, cleanRoot+string(os.PathSeparator)) && evaluated != cleanRoot {
			return errors.New("symlink escapes root")
		}
	}
	return nil
}
