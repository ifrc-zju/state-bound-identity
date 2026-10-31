# 状态约束数字身份验证

面向链上链下协同的数字身份验证实验实现，对应指标2.1。链上维护身份和凭据状态，链下在固定区块高度核验签名、主体绑定、接收方和一次性挑战，约束过期、撤销及重放请求。

[技术报告](docs/technical-report.pdf) · [历史统计数据](data/published-results/) · [发布验证](docs/VALIDATION.md)

## 方法与代码

- `tools/Registry.sol`：身份、凭据及权限状态登记。
- `tools/verifier.py`：签名、链状态、接收方及nonce消费检查。
- `tools/run_experiment.py`：启动两节点测试链与验证服务，生成正常及拒绝用例。
- `tools/independent_audit.py`：独立检查签名、交易、区块、状态转换和统计。

## 安装与运行

需要 Python 3.12、Geth **1.13.15** 和 solc **0.8.24**。将 geth、solc 加入 PATH，或设置 `GETH_BINARY`、`SOLC_BINARY` 为可执行文件的完整路径。Geth 必须使用上述支持 Clique 的版本；新版已移除该出块方式，见[官方说明](https://geth.ethereum.org/docs/fundamentals/private-network)。程序只连接本机新建测试链，不连接主网。

```bash
python -m venv .venv
# Windows: .venv/Scripts/activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell 设置示例：

```powershell
$env:GETH_BINARY = "C:/tools/geth.exe"
$env:SOLC_BINARY = "C:/tools/solc.exe"
```

独立复核还需要Node.js，并要求`node`在PATH中。

```bash
python tools/run_experiment.py --mode smoke
python tools/independent_audit.py <上一步输出的运行编号>
```

基础集成测试覆盖28条用例。运行编号格式为`smoke_日期时间_随机后缀`。程序新建测试账户和本地链，结束后停止本轮启动的进程；测试目录包含一次性私钥，不应提交到仓库。默认RPC端口18545、18546，运行期间应避免启动相同端口的另一个实例。

接收方隔离可用`--mode audience_isolation`验证；完整批次配置见`tools/run_suite.py`。链与两个验证器均部署在本机，结果适用于这一受控配置。

## 数据与结果

`data/published-results`包含历史用例结果与性能统计，来源为2026年9月的既有实验。`docs/VALIDATION.md`记录当前发布副本的功能与独立复核结果。二者不混合统计。

## 署名与引用

技术报告作者以PDF为准。代码贡献根据实际提交与审阅记录说明；不依据报告署名推定每位作者的具体开发工作。

## 许可

仓库自有代码及配套使用说明采用[MIT许可](LICENSE)。技术报告、研究论文和第三方数据保留各自署名及权利；MIT许可不替代其原有授权。
