package limiter

import (
	"strconv"
	"sync"
	"testing"
	"time"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/format"
)

// TestLimiterConcurrentNoRace exercises the exact concurrency pattern that
// used to crash the whole process: the data path (CheckLimit, one goroutine
// per new connection) reading AliveList / OldUserOnline / SpeedLimiter while
// the control path mutates them (UpdateUser deletes, task.go replaces the
// AliveList pointer, GetOnlineDevice replaces the OldUserOnline pointer).
//
// With the old bare `map[int]int` AliveList this raced a delete/read into a
// Go runtime `fatal error: concurrent map read and map write`. With the
// atomic.Pointer + copy-on-write fix it must run clean under `-race`.
// Run: go test ./limiter/ -race -run TestLimiterConcurrentNoRace
func TestLimiterConcurrentNoRace(t *testing.T) {
	Init()
	tag := "tag"
	users := []panel.UserInfo{
		{Id: 1, Uuid: "11111111-1111-1111-1111-111111111111", DeviceLimit: 5},
		{Id: 2, Uuid: "22222222-2222-2222-2222-222222222222", DeviceLimit: 5},
	}
	alive := map[int]int{1: 1, 2: 1}
	l := AddLimiter("vless", tag, users, alive)

	tu1 := format.UserTag(tag, users[0].Uuid)
	tu2 := format.UserTag(tag, users[1].Uuid)

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// 8 data-path readers (simulate concurrent new connections).
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "10.0.0." + strconv.Itoa(i)
			for {
				select {
				case <-stop:
					return
				default:
					l.CheckLimit(tu1, ip, true)
					l.CheckLimit(tu2, ip, true)
				}
			}
		}(i)
	}

	// Control path A: UpdateUser deletes then re-adds user 1 (COW AliveList
	// delete + SpeedLimiter/UserOnlineIP churn).
	wg.Add(1)
	go func() {
		defer wg.Done()
		del := []panel.UserInfo{{Id: 1, Uuid: users[0].Uuid}}
		add := []panel.UserInfo{{Id: 1, Uuid: users[0].Uuid, DeviceLimit: 5}}
		for {
			select {
			case <-stop:
				return
			default:
				l.UpdateUser(tag, nil, del, nil)
				l.UpdateUser(tag, add, nil, nil)
			}
		}
	}()

	// Control path B: task.go-style whole-map replacement of AliveList.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				nm := map[int]int{1: 2, 2: 3}
				l.AliveList.Store(&nm)
			}
		}
	}()

	// Control path C: online-device report replaces OldUserOnline pointer.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = l.GetOnlineDevice()
			}
		}
	}()

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}
