package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go maps maps.c

import (
        "context"
        "log"
        "math/rand"      
        "os"
        "os/signal"
        "runtime"         
        "syscall"
        "time"            

        "github.com/cilium/ebpf"
        "github.com/cilium/ebpf/rlimit"
)

func main() {
        // Build a cancellable context that closes on Ctrl-C or SIGTERM.
        ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
        defer stop()

        // Allow the current process to lock memory for eBPF resources.
        if err := rlimit.RemoveMemlock(); err != nil {
                log.Fatal(err)
        }

        // Load pre-compiled programs and maps into the kernel.
        var objs mapsObjects
        if err := loadMapsObjects(&objs, nil); err != nil {
                log.Fatal(err)
        }
        defer objs.Close()

        // ------------------------------------------------------------
        // ADD: Populate the maps with random data once at startup
        // ------------------------------------------------------------
        rand.Seed(time.Now().UnixNano())
        numCPU := runtime.NumCPU()

        // Helper that returns a random u32
        rndU32 := func() uint32 { return uint32(rand.Intn(1 << 31)) }

        // ----- hash_map -----
        for i := uint32(0); i < 5; i++ { // fewer than max_entries
                if err := objs.HashMap.Put(i, rndU32()); err != nil {
                        log.Fatalf("hash_map: %v", err)
                }
        }

        // ----- lru_hash_map -----
        for i := uint32(0); i < 5; i++ { // fewer than max_entries
                if err := objs.LruHashMap.Put(i, rndU32()); err != nil {
                        log.Fatalf("hash_map: %v", err)
                }
        }

        // ----- percpu_hash_map -----
        for i := uint32(0); i < 5; i++ {
                // Build a per-CPU slice: one value per CPU
                vals := make([]uint32, numCPU)
                for c := range vals {
                        vals[c] = rndU32()
                }
                if err := objs.PercpuHashMap.Put(i, vals); err != nil {
                        log.Fatalf("percpu_hash_map: %v", err)
                }
        }

        // ----- lru_percpu_hash_map -----
        for i := uint32(0); i < 5; i++ {
                // Build a per-CPU slice: one value per CPU
                vals := make([]uint32, numCPU)
                for c := range vals {
                        vals[c] = rndU32()
                }
                if err := objs.PercpuLruHashMap.Put(i, vals); err != nil {
                        log.Fatalf("percpu_hash_map: %v", err)
                }
        }

        // ----- array_map -----
        for i := uint32(0); i < 5; i++ {
                if err := objs.ArrayMap.Put(i, rndU32()); err != nil {
                        log.Fatalf("array_map: %v", err)
                }
        }

        // ----- percpu_array_map -----
        for i := uint32(0); i < 5; i++ {
                vals := make([]uint32, numCPU)
                for c := range vals {
                        vals[c] = rndU32()
                }
                if err := objs.PercpuArrayMap.Put(i, vals); err != nil {
                        log.Fatalf("percpu_array_map: %v", err)
                }
        }

	// ----- lpm_trie_map -----
	// TODO: Does it have a counter?
	type lpmKey struct {
		Prefixlen uint32
		Data      uint32
	}

	for i := uint32(0); i < 5; i++ {
		key := lpmKey{
			Prefixlen: 32, // a /32 prefix (exact-match) …
			Data:      i,  // … where “data” is just the number i
		}
		if err := objs.LpmTrieMap.Put(key, rndU32()); err != nil {
			log.Fatalf("lpm_trie_map: %v", err)
		}
	}

	// ----- queue_map -----
	// Not yet supported to push values from user space
	/*
	for i := 0; i < 5; i++ {
		val := rndU32()

		if err := queuePush(objs.QueueMap, val); err != nil {
			log.Fatalf("queue_map push: %v", err)
		}
	}
	*/

        log.Println("Random values loaded into eBPF maps. Press Ctrl-C to exit.")
        // ------------------------------------------------------------

        // Block here until we receive a signal.
        <-ctx.Done()
}
