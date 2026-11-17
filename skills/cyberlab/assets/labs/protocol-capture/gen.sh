#!/bin/sh
# Exercise the protocol's message types with its own client. Exit non-zero on any failure.
set -e
host="$1"; sleep 2   # let tcpdump start
redis-cli -h "$host" PING
redis-cli -h "$host" SET greeting "hello lab"
redis-cli -h "$host" GET greeting
redis-cli -h "$host" INCR counter
redis-cli -h "$host" LPUSH queue a b c
redis-cli -h "$host" LRANGE queue 0 -1
redis-cli -h "$host" HSET user:1 name alice role admin
redis-cli -h "$host" HGETALL user:1
redis-cli -h "$host" GET missing-key
redis-cli -h "$host" NOSUCHCOMMAND || true   # error reply branch
