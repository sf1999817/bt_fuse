#!/bin/bash

# 测试函数
run_command_test() {
    local command=$1
    local iterations=$2
    local output_file=$3

    echo "Testing command: $command with $iterations iterations..."

    total_time=0

    for ((i=0; i<$iterations; i++)); do
        # 使用 /usr/bin/time 来获取更详细的时间信息
        start_time=$(date +%s%N)
        eval "$command" > /dev/null
        end_time=$(date +%s%N)
        elapsed=$(( ($end_time - $start_time) / 1000000 ))  # 转换为毫秒
        total_time=$(echo "$total_time + $elapsed" | bc)
    done

    average_time=$(echo "$total_time / $iterations" | bc)
    echo "Average elapsed time per iteration: $average_time ms" > "$output_file"
}

# 创建一个测试目录和文件
prepare_test_environment() {
    local mount_point=$1
    local num_files=$2

    echo "Preparing test environment in $mount_point with $num_files files..."

    mkdir -p "$mount_point"
    for ((i=0; i<num_files; i++)); do
        touch "$mount_point/test_file_$i.txt"
    done
}

# 准备测试环境
prepare_test_environment /home/sf/os/fuses 1000

# 运行测试
run_command_test "find /home/sf/os/fuses -type f" 100 test_results.txt

# 打印结果
cat test_results.txt
