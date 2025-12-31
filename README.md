# ECH Workers Android 客户端

基于 gomobile 的 Android VPN 客户端，支持 ECH (Encrypted Client Hello) 加密。

## 功能特性

- ✅ WebSocket + TLS 1.3 传输
- ✅ ECH (Encrypted Client Hello) 支持
- ✅ Yamux 多路复用
- ✅ VPN 全局代理
- ✅ 分应用代理（白名单/黑名单模式）
- ✅ 节点管理

## 项目结构

```
android/
├── core/                    # Go 核心库
│   ├── core.go             # 核心网络代码
│   ├── go.mod              # Go 模块定义
│   └── build.sh            # 编译脚本
├── app/                     # Android 应用
│   ├── src/main/
│   │   ├── java/com/echworkers/android/
│   │   │   ├── MainActivity.kt
│   │   │   ├── AppProxyActivity.kt
│   │   │   ├── model/
│   │   │   ├── service/
│   │   │   ├── ui/
│   │   │   ├── viewmodel/
│   │   │   └── vpn/
│   │   ├── res/
│   │   └── AndroidManifest.xml
│   ├── build.gradle.kts
│   └── libs/               # gomobile 生成的 AAR
├── build.gradle.kts
├── settings.gradle.kts
└── README.md
```

## 编译步骤

### 1. 编译 Go 核心库

需要先安装 gomobile：

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

然后编译 AAR：

```bash
cd core
./build.sh
# 或者手动执行：
# gomobile bind -target=android -androidapi 21 -o ../app/libs/core.aar .
```

### 2. 编译 Android 应用

使用 Android Studio 打开 `android` 目录，或使用命令行：

```bash
./gradlew assembleRelease
```

APK 输出位置：`app/build/outputs/apk/release/app-release.apk`

## 注意事项

1. **Go 版本**：需要 Go 1.23+ 以支持原生 ECH (Encrypted Client Hello)
2. **TUN2SOCKS**：当前 VPN 服务需要集成 tun2socks 库来实现 TUN 设备到 SOCKS5 的转发
3. **最低 API**：Android 5.0 (API 21)

## TODO

- [x] ECH 支持（Go 1.23+ 原生支持）
- [ ] 集成 tun2socks 库
- [ ] 添加流量统计
- [ ] 添加延迟测试
- [ ] 添加订阅导入功能
