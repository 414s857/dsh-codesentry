/**
 * Built-in demonstration Skills.
 *
 * 说明：提示词（prompts）与 Skill 的分工
 * ----------------------------------------------------------------------------
 * - 提示词 = 单一漏洞类型的「检查清单」。粒度细、可自由勾选组合，适合"我只想
 *   重点审 SQL 注入和越权"这类有明确目标的范围性审计。
 * - Skill = 一整套「审计方法论」（SKILL.md + references/）。不可拆分、整体套用，
 *   除了漏洞清单，还规定了"怎么找入口、怎么顺数据流、授权边界怎么核、怎么判误报、
 *   怎么定级、怎么组织报告"的完整打法。
 *
 * 内置这两个 Skill 既是可直接使用的模板，也是"两者区别"的示范：
 *   - 「Web 应用全量审计方法论」：从入口到 sink 的系统化流程，覆盖全部漏洞家族；
 *   - 「Java 反序列化深度审计」：单一高危领域的纵深打法，附带 gadget 速查 reference。
 * 用户可以照抄它们的结构，改为自己团队的语言、框架与判定口径。
 */

const WEB_METHODOLOGY = `## 0. 适用场景

用于对一个 Web 应用后端（多语言均可）做**系统化全量审计**。目标不是"逐条跑清单"，而是先建立"攻击面地图"，再沿可控输入到危险汇集点（sink）的数据流逐个确认。

## 1. 建立攻击面地图（先做，不要急着读实现）

1. 先列出**入口（source）**：
   - 路由/控制器清单（Spring Controller、Express/Koa router、Gin/Echo handler、Django/Flask view、Rails controller、ASP.NET Controller）；
   - 过滤器 / 拦截器 / 中间件（鉴权、参数解析、CORS、请求体解析）；
   - 定时任务、消息消费者、Webhook 接收、文件导入、CLI 参数入口；
   - 前端可见的接口（从静态资源、API 客户端代码、OpenAPI/Swagger 反推）。
2. 再列出**危险汇集点（sink）**：
   - 数据库访问（拼接 SQL、原生查询、ORM 动态语句）；
   - 命令/进程执行（exec、ProcessBuilder、subprocess、Runtime、shell）；
   - 文件系统（读写、上传、解压、路径拼接）；
   - 反序列化 / 表达式 / 模板求值；
   - 出网请求（HTTP 客户端、URL 打开、代理）；
   - 反序列化、加密、日志。
3. 用 grep 快速定位危险 API（见第 3 节速查表），宁可多列候选，再逐一排除。

## 2. 数据流分析（核心工作）

1. 对每个入口，跟踪参数 -> 校验 -> 业务 -> sink 的完整路径；注意**跨文件、跨中间件**的传递（controller -> service -> dao）。
2. 判断每个"可控点"是否真的可控：是否来自 HTTP 参数 / Header / Cookie / Body / 文件 / MQ / DB 二次注入。
3. 判断"卡点"是否有效：参数化绑定、白名单、类型强制、上下文编码、鉴权中间件、对象归属校验。**只有卡点确认缺失才成漏洞。**
4. 特别关注**共享安全边界**（统一鉴权、全局输入过滤、SQL 工具类、加解密工具、模板渲染封装）：一处缺失往往影响所有调用点，优先级最高。

## 3. 危险 API 速查（grep 起点）

- SQL：\`+ "select"\`、String.format、\${}、\${...}（MyBatis）、raw()、createNativeQuery、execSQL、ORDER BY/LIMIT 拼接。
- 命令：Runtime.getRuntime().exec、ProcessBuilder、subprocess/os.system/os.popen、child_process.exec/execSync、system()、popen。
- 路径：new File(user)、Paths.get(user)、filepath.Join、path.join、os.path.join、realpath/resolve 后的前缀校验。
- 反序列化：ObjectInputStream、readObject、XStream、Fastjson autoType、Jackson enableDefaultTyping、Hessian、pickle.loads、yaml.load、unserialize。
- 模板/表达式：TemplateEngine.process、SpelExpressionParser、OGNL、MVEL、Jinja2 Environment、Twig、Freemarker、eval/Function。
- SSRF：URL().openConnection、HttpClient、requests.get、axios.get、http.Get、RestTemplate、OkHttp，参数来自请求。
- 上传/XXE：MultipartFile、FileItem、DocumentBuilderFactory、SAXParserFactory、XMLInputFactory、libxml 实体解析。

## 4. 授权与访问控制（高频、易漏，单独一轮）

1. 逐个写接口核对：是否只校验"已登录"却没校验"这个对象属于当前用户"（IDOR / 水平越权）。
2. 管理接口、内部接口是否可达、是否二次鉴权。
3. 批量赋值（Mass Assignment）：请求体字段是否直接绑定到实体（role、is_admin、balance、price 可被客户端提交）。
4. 权限模型是否统一（集中鉴权中间件 vs 每个接口手写），找出遗漏的接口。

## 5. 判定、定级与误报

1. 先看**是否可达**（路由是否注册、鉴权是否绕过、前置校验是否可通过），不可达不报。
2. 定级参考：RCE / 任意文件读写 / 认证或管理员绕过 / 任意数据读写 = critical；水平越权、存储型 XSS、SSRF 达内网 = high；受限场景 = medium；信息性 = low/info。
3. 误报优先排除：常量/枚举来源、已参数化、已有可靠鉴权与归属校验、仅测试/示例值。

## 6. 报告要求

- 每条发现必须给出：相对路径 + 行号、关键代码片段、source -> sink 的完整触发链、可利用的 PoC 请求（HTTP 原始请求 + curl）、修复建议。
- 同一根因影响多处时合并报告，列出所有受影响位置。
- 最后给出整体风险判断、已覆盖与未覆盖的入口/模块说明。`

const WEB_METHODOLOGY_REF = `# Web 审计常见框架速查

## Spring / Spring Boot
- 鉴权：SecurityFilterChain、@PreAuthorize、自定义 Interceptor；检查 permitAll 范围与路径匹配绕过（/admin/、/admin//、;.json）。
- SQL：JdbcTemplate 拼接、MyBatis \${}、JPA createNativeQuery。
- SpEL：@Value 求值、SpelExpressionParser、Thymeleaf 表达式。
- Actuator：/actuator/env、/actuator/heapdump 未授权暴露。

## Node / Express / Koa
- 原型链污染：lodash.merge/set、Object.assign 深层、qs 解析、express json 解析 __proto__。
- 命令：child_process.exec(user)、execSync 拼接。
- SSRF：axios.get(req.query.url)、node-fetch、http.get。
- 模板：EJS <%= %> 用错为 <%- %>、pug 未转义。

## Python / Django / Flask
- SQL：raw()、extra()、cursor.execute 拼接。
- 命令：subprocess(shell=True)、os.system、eval。
- 反序列化：pickle.loads、yaml.load（非 safe_load）。
- 模板：Jinja2 from_string(user)、render_template_string。

## PHP
- SQL：mysqli 拼接、PDO query 拼接。
- 命令：system/exec/shell_exec/passthru/popen/反引号。
- 反序列化：unserialize(user)、Phar 反序列化。
- 上传：move_uploaded_file 未校验扩展名/内容。

## Java 反序列化速查（详见「Java 反序列化深度审计」Skill）
- 入口：readObject、XStream.fromXML、JSON.parseObject(autoType)、Hessian readObject。
- 链：CommonsCollections、CommonsBeanutils、Spring、Groovy、JdbcRowSetImpl(JNDI)。`

/**
 * 内置示范 Skill 列表。字段与 store.createSkill 的入参对齐。
 * references 为 [{ path, content }]，会在组装 Skill 提示时被内联。
 */
export const BUILTIN_SKILLS = [
  {
    name: 'Web 应用全量审计方法论',
    category: '方法论',
    description:
      '从入口到 sink 的系统化 Web 审计流程：先建攻击面地图，再顺数据流逐点确认，覆盖注入、越权、SSRF、文件、反序列化、SSRF、配置等全部漏洞家族。用于需要"整体打法"而不只是单类清单的审计。',
    content: WEB_METHODOLOGY,
    report_guide:
      '报告需按「攻击面地图 → 每类发现（路径:行号 + 代码 + source→sink + PoC + 修复）→ 覆盖说明」组织；同一根因多处受影响合并为一条并列出所有位置。',
    references: [
      { path: 'references/frameworks.md', content: WEB_METHODOLOGY_REF },
    ],
  },
  {
    name: 'Java 反序列化深度审计',
    category: '深度专项',
    description:
      '针对 Java 反序列化 / JNDI 注入的纵深审计打法：枚举反序列化入口、识别可利用 gadget 链、确认可控性、给出可利用性判断与 PoC。属于单一高危领域的整体套用型方法论。',
    content: `## 1. 目标
找出所有把不可信字节流送入 Java 反序列化 / JNDI 查找 / 表达式求值的入口，并判断是否存在可利用的 gadget 链。

## 2. 入口枚举（source）
1. ObjectInputStream.readObject / readUnshared 的反序列化点。
2. 第三方封装：XStream.fromXML、Fastjson JSON.parseObject/parse（autoType）、Jackson enableDefaultTyping / @JsonTypeInfo、Hessian2Input.readObject、Kryo、JBoss Marshalling、SnakeYAML。
3. Session / 缓存 / MQ / RMI / HTTP Body 中承载的序列化数据。
4. JNDI：InitialContext.lookup(user)、Spring JndiObjectFactoryBean、RMI Registry。

## 3. Gadget 链识别（sink / 可利用性）
1. classpath 中是否存在可被链式调用的库（见 references/gadgets.md）；用依赖清单 + import 判断。
2. 反序列化前是否有类型白名单（ObjectInputFilter、Fastjson safeMode、XStream allowTypes、Jackson 无多态）。
3. 是否存在 JNDI 注入到可控 LDAP/RMI（JDK 版本、com.sun.jndi.ldap.object.trustURLCodebase 设置）。

## 4. 判定与定级
1. 不可信数据进入上述入口且无有效白名单/过滤器 -> 漏洞。
2. 能触发已知 gadget 达到 RCE -> critical；只能触发有限影响 -> high/medium。
3. 误报排除：固定内部对象、已启用严格白名单、数据来自可信存储且不可篡改。

## 5. 报告
给出入口路径:行号、承载数据的请求/字段、命中的 gadget 链、构造 PoC（可用 ysoserial 思路说明关键字节与参数）、修复建议（升级/加白名单/换安全格式）。`,
    report_guide: '每条按「入口(路径:行号) → 可控性 → 命中 gadget → 可利用性(critical/high) → PoC → 修复」组织。',
    references: [
      {
        path: 'references/gadgets.md',
        content: `# Java 反序列化常见 gadget 链速查

## 依赖触发点
- commons-collections 3.1/3.2/4.x：InvokerTransformer / TransformedMap / LazyMap -> 命令执行。
- commons-beanutils：BeanComparator + TemplatesImpl。
- spring-core / spring-beans：MethodInvokeTypeProvider / PropertyPathFactoryBean。
- groovy：MethodClosure + ConvertedClosure -> 命令执行。
- rome / xalan / c3p0 / jython 等历史链。

## JNDI 注入
- JdbcRowSetImpl.setAutoCommit -> 触发 JNDI lookup -> 可控 LDAP 返回恶意 Reference。
- 关键：JDK 版本决定是否允许远程 codebase；高版本需本地 gadget（如 Tomcat BeanFactory + EL）。

## 安全配置要点（用于判定是否可利用）
- ObjectInputFilter（JDK9+）是否设置白名单。
- Fastjson：safeMode / autoTypeSupport=false / 版本 >= 1.2.83。
- Jackson：未开启 enableDefaultTyping、无 @JsonTypeInfo 的 Object 字段。
- XStream：allowTypes / 安全框架初始化。
`,
      },
    ],
  },
]
