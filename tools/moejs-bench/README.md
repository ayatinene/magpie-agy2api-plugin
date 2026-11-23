# moejs-bench

在 Magpie 实际使用的 `moejs` 引擎中运行 `middleware.mjs`（`onProvider`），检查每个用例是否在时间预算（默认 250ms）内完成且输出与 Node 完全一致（需 Go 1.26+）。

```bash
cd tools/moejs-bench
node gen-corpus.mjs /tmp/corpus.ndjson
go run . ../.. /tmp/corpus.ndjson        # 可选第三个参数：预算毫秒数，默认 250
```
