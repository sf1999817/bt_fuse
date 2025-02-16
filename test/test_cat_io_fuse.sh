#!/bin/bash

# 测试函数
run_command_test() {
    local command=$1
    local iterations=$2

    echo "Testing command: $command with $iterations iterations..."

    total_time=0

    for ((i=0; i<$iterations; i++)); do
        start_time=$(date +%s%N)
        eval "$command" > /dev/null
        end_time=$(date +%s%N)

        elapsed=$(( ($end_time - $start_time) / 1000000 ))
        total_time=$((total_time + elapsed))
    done

    average_time=$(( total_time / iterations ))
    echo "Average elapsed time per iteration: $average_time ms"
}

# 运行测试
run_command_test "cat /home/sf/os/fuses/testfile.txt" 100000
