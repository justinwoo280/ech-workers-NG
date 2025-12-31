#!/bin/bash
# 编译 Android AAR 库
# 锁定 gomobile 版本以确保构建稳定性

set -e

GOMOBILE_VERSION="v0.0.0-20231127183840-76ac6878050a"

echo "=== 安装 gomobile (版本: $GOMOBILE_VERSION) ==="
go install golang.org/x/mobile/cmd/gomobile@$GOMOBILE_VERSION
go install golang.org/x/mobile/cmd/gobind@$GOMOBILE_VERSION

echo "=== 初始化 gomobile ==="
gomobile init

echo "=== 下载依赖 ==="
go mod tidy

echo "=== 编译 Android AAR ==="
gomobile bind -v -target=android -androidapi 21 -o ../app/libs/core.aar .

echo "=== 编译完成 ==="
ls -lh ../app/libs/core.aar
