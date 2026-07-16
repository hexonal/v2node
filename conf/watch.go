package conf

import (
	"fmt"
	"log"
	"time"

	"github.com/fsnotify/fsnotify"
)

func (p *Conf) Watch(filePath string, reload func()) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("new watcher error: %s", err)
	}
	go func() {
		var pre time.Time
		defer watcher.Close()
		for {
			select {
			case e := <-watcher.Events:
				if e.Has(fsnotify.Chmod) {
					continue
				}
				// A write-temp-file-then-rename edit (the common atomic-write
				// pattern used by editors and config-management tools, and
				// exactly what this code's own 5s reload delay seems to be
				// defending against for torn reads) unlinks the inode this
				// watch is on - the kernel auto-removes the inotify watch,
				// and without re-adding it here every subsequent edit would
				// go completely unnoticed forever, with no error or log to
				// indicate hot-reload had silently stopped working. The path
				// itself still exists (pointing at the new inode), so a
				// plain re-Add is enough. Done unconditionally, even inside
				// the debounce window below, so a rename landing right after
				// another edit can't permanently drop the watch.
				if e.Has(fsnotify.Remove) || e.Has(fsnotify.Rename) {
					if err := watcher.Add(filePath); err != nil {
						log.Printf("re-watch file error: %s", err)
					}
				}
				if pre.Add(10 * time.Second).After(time.Now()) {
					continue
				}
				pre = time.Now()
				go func() {
					time.Sleep(5 * time.Second)
					log.Println("config file changed, reloading...")
					*p = *New()
					err := p.LoadFromPath(filePath)
					if err != nil {
						log.Printf("reload config error: %s", err)
					}
					reload()
					log.Println("reload config success")
				}()
			case err := <-watcher.Errors:
				if err != nil {
					log.Printf("File watcher error: %s", err)
				}
			}
		}
	}()
	err = watcher.Add(filePath)
	if err != nil {
		return fmt.Errorf("watch file error: %s", err)
	}
	return nil
}
