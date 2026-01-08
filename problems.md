针对你目前扩展至 7 门语言（C, C++, JS, C#, Java, Python, Go）的宏大计划，结合你之前遇到的 Token 爆炸教训，**最佳计划建议**是采用"**核心逻辑统一 + 语言策略解耦**"的架构模式。

这份计划旨在让你在不破坏现有 C/C++/JS 稳定性的前提下，实现高效的横向扩展。

---

### 一、 核心架构：策略模式 (Strategy Pattern)

不要在主循环中使用大量的 `if-else` 来判断语言。根据你提供的方案，应当将每种语言的特殊性封装在独立的策略类中。

* **配置中心 (`language_config.py`)**：统一管理各语言的 CodeQL 查询路径、Token 限制（`code_size_limit`）和系统提示词增强（`system_prompt_additions`）。
* **策略基类 (`base.py`)**：定义提取代码、构建 Prompt 和后处理响应的标准接口。
* **具体语言策略**：
* **Java 策略**：调高 `class_size_limit`（建议 1500+），因为 Java 模板代码较多。
* **JavaScript 策略**：强制执行 `jsbeautifier` 逻辑，处理压缩混淆文件。
* **Go 策略**：保持中等 `code_size_limit`，侧重于处理 Goroutine 并发安全和 SQL 注入。
* **Python 策略**：关注装饰器和缩进完整性，防止截断导致语法错误）。



---

### 二、 实施阶段划分

#### 第一阶段：架构重构（预计 1-2 天）

* **建立工厂模式**：实现一个根据语言名称自动返回对应策略类的加载器。
* **集成元数据容错**：修改 `db_lookup.py`，使其能灵活处理不同语言的 CSV 文件。例如，C# 和 Java 强依赖 `Classes.csv`，而 Python/JS 可能更依赖 `Functions.csv`。

#### 第二阶段：语言适配循环（每门语言 1 天）

1. **准备 QL 库**：在 `data/queries/{lang}` 放置该语言专用的 CodeQL 查询文件。
2. **定义模板**：在 `data/templates/{lang}` 编写针对该语言常见漏洞（如 C# 的反序列化、Go 的命令执行）的专属 Prompt 模板。
3. **针对性截断**：在策略类中微调该语言的 `max_chars` 或截断算法（如 C# 的 Getter/Setter 过滤）。

#### 第三阶段：全局"防御性"增强

* **Token 熔断器**：在所有语言的工具调用接口处增加硬上限拦截，防止任何语言因抓取巨型文件导致 62 万 Token 的悲剧再次发生。
* **缓存库隔离**：建议在 `llm_cache.db` 中按语言维度增加索引，避免不同语言间相似代码块的误匹配。

---

### 三、 关键参数推荐表

| 语言 | `code_size_limit` (行) | 审计重点 (System Prompt) | 提取特殊性 |
| --- | --- | --- | --- |
| **Java** | 300 - 500 | Spring Bean, 反序列化, SQL 注入 | 必须保留完整的类定义头部 |
| **C#** | 300 - 400 | .NET 反序列化, LINQ 注入, 命令执行 | 过滤无用的 Property 定义 |
| **Go** | 400 - 600 | 并发竞争 (Race), 缓冲区溢出, 指针不安全 | 关注 `defer` 和 `go` 关键字上下文 |
| **Python** | 350 - 500 | `eval`/`exec`, Pickle 风险, 框架路径 | 确保 `try-except` 块的完整性 |
| **JS/TS** | 200 (美化后) | 原型污染, XSS, Node.js 命令执行 | **强制反混淆/美化后再截断** |

---

### 四、 下一步行动建议

#### 已完成 ✅

- [x] 创建 `src/llm/strategies/` 目录结构
- [x] 创建策略基类 `base.py`
- [x] 创建语言配置中心 `language_config.py`
- [x] 创建策略工厂 `factory.py`
- [x] 在 `vulnhalla.py` 中集成策略模式（最小改动）
- [x] 创建默认策略 `default_strategy.py`

#### 待完成

- [ ] 创建具体语言策略（C++, JavaScript 等）
- [ ] 使用策略的 `should_skip_file()` 替换硬编码的 `is_static_resource()`
- [ ] 使用策略的 `extract_function_code()` 替换现有逻辑
- [ ] 使用策略的 `build_prompt()` 替换现有模板构建
- [ ] 集成 JS beautifier 到 JavaScript 策略
- [ ] 添加 Token 熔断器硬上限拦截
- [ ] 创建 Java 策略（高 class_size_limit）
- [ ] 创建 Python 策略（装饰器完整性）
- [ ] 创建 Go 策略（并发安全）
- [ ] 创建 C# 策略（.NET 反序列化）
