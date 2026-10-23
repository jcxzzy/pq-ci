# pq-port 宿主构建：目标是 arm64（Apple silicon / iOS）。
# 本仓库的 Intel Mac 只做交叉编译验证（clang -arch arm64 -c），不能本机运行——
# 运行验证在 bootsim.py（Unicorn 模拟）或 Apple silicon 机器上进行。
CC = clang
CFLAGS = -arch arm64 -O2 -Wall -Wextra -target arm64-apple-macos11
MTLFLAGS = -fobjc-arc -framework Metal -framework Foundation

all: dmhost

dmhost: dmhost.c fault.c entry.S nvn_mtl.m
	$(CC) $(CFLAGS) -c dmhost.c -o dmhost.o
	$(CC) $(CFLAGS) -c fault.c -o fault.o
	$(CC) $(CFLAGS) -c entry.S -o entry.o
	$(CC) $(CFLAGS) $(MTLFLAGS) -c nvn_mtl.m -o nvn_mtl.o
	$(CC) $(CFLAGS) -o dmhost dmhost.o fault.o entry.o nvn_mtl.o $(MTLFLAGS)

check: dmhost.c fault.c entry.S nvn_mtl.m
	$(CC) $(CFLAGS) -fsyntax-only dmhost.c
	$(CC) $(CFLAGS) -fsyntax-only fault.c
	$(CC) $(CFLAGS) $(MTLFLAGS) -fsyntax-only nvn_mtl.m
	@echo "交叉编译检查通过（arm64）"

clean:
	rm -f dmhost dmhost.o fault.o entry.o nvn_mtl.o

.PHONY: all check clean
