#!/bin/bash

# Default values
port=19000
n=1
host=localhost

# Parse options
while getopts p:n:h: flag
do
    case "${flag}" in
        p) port=${OPTARG};;
        n) n=${OPTARG};;
        h) host=${OPTARG};;
        *);;
    esac
done

# Calculate the range of ports based on n
end_port=$((port + n - 1))

# Print configuration info
echo "Configuration:"
echo "Host: $host"
echo "Starting port: $port"
echo "Number of ports: $n"
echo "End port: $end_port"

# Execute the parallel command with the calculated range
parallel --tag --line-buffer python3 -u sensor.py \
                                        --ipfix -p ipfix_info_export \
                                        --ipfix_export_host "$host" \
                                        --ipfix_listen_port {} \
                                        ::: $(seq "$port" $end_port)
