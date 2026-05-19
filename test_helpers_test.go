package main

import (
	"os"
	"path/filepath"
)

// writeFileAtomic writes content to path via a temp file in the same dir,
// fsyncs, and atomically renames into place. Used by tests that need to
// stage fixture files; production code persists via bbolt and does not need
// this helper.
func writeFileAtomic(path string, content []byte, perm os.FileMode) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	dirFile, err := os.Open(dir) //nolint:gosec // test helper; directory is created by the test.
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}
