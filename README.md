# firewall

## build

### kernel module

1. 前置条件：
    * Linux Kernel >= 5.4.72（由于未适配低版本内核，可能需要手动修改代码）
    * GCC, Make, etc.
2. 调整：
    * 打开`lkm.c`，视情况修改`LAN_IP`、`LAN_MASK`与`REJECT_BY_DEFAULT`（默认拒绝会导致后续过程中无法在开发环境下运行前端）
3. 编译：
    * `cd module`，再执行`make`
4. 安装模块：
    * `insmod lkm.ko`（普通用户需要提权）

### userspace program

1. 前置条件：由于本项目使用Node C++ Addon实现前端与内核模块的通信，因此除常规的编译工具外，还需要如下工具，版本越高越好
    * Node.js >= 14.12.0
    * yarn (部分发行版中也叫yarnpkg)
    * CMake >= 3.0.0
2. 安装依赖：
    * `cd userspace`，再执行`yarn`
3. 在开发环境下运行：
    * `cd src/cpp`，初始化CMake`mkdir -p build/Debug && cd build/Debug && cmake ../../ -DCMAKE_BUILD_TYPE="Debug" && cd ../../`
    * 执行`yarn start`，该命令会在3000端口开启dev server，并启动前端（同时可能会启动浏览器，直接关掉就行）。这条命令做了三件事情：
        * `yarn build:cpp:debug`：以Debug模式构建C++ Binding
        * `yarn start:react`：使用webpack打包前端，并运行dev server
        * `yarn start:electron`：构建electron
4. 在生产环境下运行：
    * `cd src/cpp`，初始化CMake`mkdir -p build/Release && cd build/Release && cmake ../../ -DCMAKE_BUILD_TYPE="Release" && cd ../../`
    * 回到原目录`cd ../../`执行`yarn build`。这条命令做了三件事情：
        * `yarn build:cpp:release`：以Release模式构建C++ Binding
        * `yarn build:react`：使用webpack打包前端
        * `yarn build:electron`：构建electron
    * 构建产物在`dist/linux-unpacked`目录下，可执行文件为`firewall`