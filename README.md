# 内网 APT 源（FastAPI）

单发行版、单组件、单架构的 APT 软件源。每次发布先落盘、后切换
`Release`，启用 **Acquire-By-Hash**，并只保留最近两次成功发布所引用的
索引和安装包。拿到旧 `Release` 的客户端仍可按其中的 SHA-256 取回旧索引，
再按索引校验下载安装包；同名同版本重新构建也互不覆盖。

在此之上，服务还支持**构建源码绑定**：给定某个仍在发布窗口内的 `.deb`
的 SHA-256，构建者可登记其未签名 `.dsc` 与 `Checksums-Sha256` 列出的全部
源码文件；绑定成功后，即使该 `.deb` 已被回收、服务已重启，仍可按二进制
摘要取回含原始 `.dsc` 和源码文件的 tar 归档。

## 快速开始（docker compose）

```bash
docker compose up -d --build
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool
```

上传一批 `amd64` 的 `.deb`（整版发布，一次请求一批）：

```bash
curl -fsS -X POST http://127.0.0.1:8080/api/publish \
  -F files=@hello-internal_1.0.0_amd64.deb \
  -F files=@libfoo_2.1.0_amd64.deb | python3 -m json.tool
```

也可以直接用浏览器打开 <http://127.0.0.1:8080/docs> 的上传表单
（OpenAPI 文档在 `/swagger-ui`，源码绑定表单也在同一页）。

## 绑定构建源码

排查内网软件的构建问题时，拿到 `.deb` 的 SHA-256 即可取回构建者登记的
源码。在 `/swagger-ui`（或 `/docs` 表单）调用 `POST /api/sources`，填入
二进制摘要，上传**未签名**的 `.dsc` 以及它在 `Checksums-Sha256` 中列出的
每一个源码文件：

```bash
# digest 为该 .deb 的 SHA-256（64 位十六进制）
curl -fsS -X POST http://127.0.0.1:8080/api/sources \
  -F digest=<deb-sha256> \
  -F dsc=@widget_1.0.0-1.dsc \
  -F files=@widget_1.0.0.orig.tar.gz \
  -F files=@widget_1.0.0-1.debian.tar.xz
```

服务端按以下规则核对，任一不满足都返回 `400`/`409` 且不产生任何可下载
归档：

- **源包身份**取自 `.deb` 控制信息的 `Source` 字段：`Source: src (ver)`
  取括号内外的名称与版本；只有名称时版本沿用二进制 `Version`；字段缺省
  时分别沿用 `Package` 与 `Version`。`.dsc` 的 `Source`/`Version` 必须与之
  完全一致。
- **清单逐一对应**：上传的源码文件集合必须与 `Checksums-Sha256` 完全一致
  （不能缺、不能多），且每个文件的名称、大小、SHA-256 都与清单吻合。
- **首次绑定的保留引用**：绑定时该 `.deb` 必须仍被最近两次成功发布之一
  引用（保留发布引用）。已被回收或从未发布的摘要返回 `409`。
- **只接受未签名 `.dsc`**：检测到 PGP 装甲签名即拒绝。

绑定成功当次响应即给出下载地址，之后随时取回 tar（内含原始 `.dsc` 字节
与全部源码文件，平铺、确定性打包）：

```bash
curl -fsS -OJ http://127.0.0.1:8080/api/sources/<deb-sha256>
tar -tf <deb-sha256>.tar
```

重传与冲突语义：

| 再次上传的内容 | 结果 |
| --- | --- |
| 同一摘要 + 完全相同的一组原件（与 multipart 顺序无关） | `201`，返回**原下载地址**，不重复落盘 |
| 同一摘要 + 另一组原件（不同 `.dsc` 或任一文件摘要不同） | `409 Conflict`，原归档保持不变 |
| 校验失败 / 写入失败 | `400`/`5xx`，不产生可下载的新归档，无残留暂存记录 |

源码归档保存在数据卷的 `sources/archives/` 下，与 APT 文档树
`export/` 隔离，因此发布垃圾回收永远不会删除它；绑定写入采用
`staged → 落盘 fsync → committed` 的事务，重启时 `reconcile()` 会回滚未
完成写入并清理孤儿文件，已提交的绑定在重启后依旧可下载。


## 客户端配置与实测

```bash
sudo ./clients/setup-client.sh http://127.0.0.1:8080 stable main
# 等价于写入 /etc/apt/sources.list.d/internal.list：
#   deb [trusted=yes arch=amd64] http://127.0.0.1:8080/ stable main

sudo apt-get update
apt-get download hello-internal          # 下载并校验
sudo apt-get install hello-internal      # 或直接安装
```

仓库未签名，因此用 `trusted=yes`。若要签名，增加 `Release.gpg`/`InRelease`
并把 `trusted=yes` 换成 `signed-by=/usr/share/keyrings/internal.gpg`。

一键端到端验证（发布两版、`apt-get update`/`download`、旧 Release 客户端
按哈希取包、第三版触发淘汰）：

```bash
sh scripts/e2e-apt.sh http://127.0.0.1:8080
```

实测输出示例：

```
== release 1 published (index 71440bc1...)
== apt-get download smoke-one -> smoke-one_1.0.0_amd64.deb
== release 2 published (index 6fc51fd9...)
== apt-get download smoke-two -> smoke-two_2.0.0_amd64.deb
== previous release index and packages verified via by-hash
== retention keeps exactly the two most recent releases
== OK
```

## 发布语义

| 需求 | 实现 |
| --- | --- |
| 新版编制期间继续供包 | 新索引/包先写入不可变路径（`by-hash/SHA256/<hash>`、内容寻址的 pool 文件），旧 `Release` 与旧索引在此期间保持不变 |
| 切换时索引与包同时可下载 | `Release` 用原子 `rename` 作为唯一提交点；在此之前所有被引用的文件都已 fsync 落盘 |
| 旧 Release 客户端仍可取旧索引 | `Acquire-By-Hash: yes` + `dists/stable/main/binary-amd64/by-hash/SHA256/<sha256>`，`dists/stable/by-hash/SHA256/<sha256>` 亦提供 Release 本体 |
| 同名同版本重发 | pool 文件名带内容哈希：`<pkg>_<ver>_<arch>_<sha16>.deb`，两版并存 |
| 只开放最近两次成功发布 | GC 以 journal 中最新 2 条 `committed` 记录为根，删除其余 by-hash 索引与 pool 文件 |
| 坏包 / 提交前中断两版照旧 | 上传先完整校验；任一文件非法则整批拒绝。提交中断时旧 `Release` 不变，重启后 `reconcile()` 回滚 |
| 重启后仍可取用 | 启动时对比磁盘上 `Release` 的哈希与 journal 中 `staged` 记录：一致则补记为 `committed`，否则标记 `aborted` 并清理 |

### 目录结构（数据卷内）

```
/data
├── export/                                  # 只读 HTTP 根目录
│   ├── dists/stable/Release
│   ├── dists/stable/by-hash/SHA256/<release-sha256>
│   ├── dists/stable/main/binary-amd64/Packages(.gz)
│   ├── dists/stable/main/binary-amd64/by-hash/SHA256/<index-sha256>
│   └── pool/main/<bucket>/<pkg>/<pkg>_<ver>_<arch>_<sha16>.deb
├── sources/
│   └── archives/<binary-sha256>.tar         # 源码绑定归档（APT GC 不触及）
├── incoming/<token>/                        # 上传暂存，提交后删除
└── state.sqlite3                            # 发布 journal 与 source_bindings 表
```

`Release` 同时列出 `Packages` 与 `Packages.gz`：APT 2.6 以未压缩名识别
索引目标，只列 `Packages.gz` 会被静默跳过（本项目最初即踩此坑）。

## API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/publish` | multipart 字段 `files`，一次一批，返回 201 与发布记录 |
| POST | `/api/sources` | 表单字段 `digest`、`dsc`、`files`，绑定源码到二进制摘要 |
| GET | `/api/sources` | 已提交的源码绑定列表 |
| GET/HEAD | `/api/sources/{sha256}` | 下载（或探测）该摘要对应的源码 tar |
| GET | `/api/status` | 当前配置、最新发布、发布历史、绑定数量 |
| GET | `/api/publications` | 发布历史（含 `aborted`） |
| GET | `/docs` | 上传表单（发布 + 源码绑定） |
| GET | `/swagger-ui` | OpenAPI 文档 |
| GET/HEAD | `/dists/...`、`/pool/...` | 仓库文件（只读） |

错误语义：包非法 / 重复的同名同版本 / 批次超限返回 `400`/`413`，且
仓库状态完全不变。源码绑定中，摘要格式或 `.dsc`/清单/身份不合法返回
`400`，无保留发布引用或与既有绑定冲突返回 `409`；任何失败都不会产生可
下载的新归档。

## 配置

| 环境变量 | 默认值 |
| --- | --- |
| `APT_REPO_DATA_DIR` | `./data`（容器内 `/data`） |
| `APT_REPO_DISTRIBUTION` | `stable` |
| `APT_REPO_COMPONENT` | `main` |
| `APT_REPO_ARCHITECTURE` | `amd64` |
| `APT_REPO_ORIGIN` / `APT_REPO_LABEL` | `Internal APT Repository` |
| `APT_REPO_RETENTION` | `2` |
| `APT_REPO_MAX_FILE_BYTES` | `536870912` |
| `APT_REPO_MAX_BATCH_FILES` / `_BYTES` | `500` / `4 GiB` |

## 操作约束

- **单写入进程**：发布通过进程内线程锁 + `flock` 串行化，`docker compose`
  固定 `--workers 1`。多副本部署时需改为共享存储上的分布式锁。
- **unsigned**：默认不签名；生产环境应补 `InRelease`/`Release.gpg`。
- **下载与 GC 竞态**：响应通过已打开的 fd 流式发送，即使文件随后被 GC
  删除，进行中的下载仍能读到完整内容（POSIX inode 语义）。
- 容器以只读根文件系统、非 root（uid 10001）、`no-new-privileges` 运行。

## 本地开发与测试

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt pytest httpx
uvicorn app.main:app --reload          # 数据写入 ./data
pytest -q                              # 42 项测试
```

测试覆盖：发布/回读、旧 Release 按哈希取旧索引与旧包、同名同版本重发、
两版保留与第三版淘汰、坏包整批拒绝、错误架构拒绝、提交前中断回滚、
提交后崩溃恢复、下载中被 GC、Release 格式与 by-hash 服务、路径穿越；
源码绑定的源身份推导（含 `Source` 缺省/裸名/带括号版本）、清单名称大小
摘要逐一核对、缺件/多件/签名 `.dsc`/坏摘要拒绝、首次绑定的保留引用、
同组原件幂等返回原地址、异组原件 `409`、写入失败不留可下载归档、
`.deb` 回收且重启后归档仍可下载。
