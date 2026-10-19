package agent

import "testing"

func TestMemoryBudgetsLeaveRoomForCoreAndKernel(t *testing.T) {
	for _, size := range []int64{256, 512, 1024} {
		total := size * mebibyte
		var sum int64
		for _, role := range []string{"run", "helper", "forward", "core"} {
			budget := memoryBudget(role, total)
			if budget <= 0 {
				t.Fatal("invalid budget")
			}
			sum += budget
		}
		if sum > total*3/5 {
			t.Fatalf("%d MiB budgets leave insufficient room for OS: %d", size, sum/mebibyte)
		}
	}
}
