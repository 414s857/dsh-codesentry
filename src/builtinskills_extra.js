/**
 * 追加的审计 Skill 包（由 builtinskills.js 合并进 BUILTIN_SKILLS）。
 * 每个 Skill = content（SKILL.md 正文）+ references（[{path, content}]）+ report_guide。
 */

const PY_METHODOLOGY = `## 0. 适用场景

用于 Python 后端（Django / Flask / FastAPI / Tornado / aiohttp / Celery 任务）的系统化审计。按"入口 → 数据流 → sink → 卡点"的次序推进，先建地图再逐点确认。

## 1. 入口枚举（source）

1. 路由：Django urls.py → views / DRF ViewSet；Flask @app.route / Blueprint；FastAPI @router.get/post + Depends。
2. 中间件 / 装饰器：@login_required、permission_classes、中间件里读取的 Header/Cookie。
3. 反序列化与解析：request.json / form / args / data、DRF serializer、msgpack、pickle、yaml。
4. 异步任务：Celery task 参数（可能来自外部消息）、定时任务、信号 signal。
5. 动态能力：eval/exec、getattr 分发、__import__、模板 render_template_string。

## 2. 关键 sink 与卡点

1. SQL：\`cursor.execute("..." + x)\`、\`raw()\`、\`extra()\`、\`RawSQL\`、ORM \`extra(where=)\`、字符串 % / f-string 拼进 SQL。卡点：\`%s\` 参数化、ORM 查询集。
2. 命令：\`os.system\`、\`os.popen\`、\`subprocess.*(shell=True)\`、\`commands\`。卡点：\`subprocess.run([...])\` 数组 + shell=False。
3. 反序列化：\`pickle.loads\`、\`yaml.load\`（非 safe_load）、\`marshal\`、\`dill\`。卡点：safe_load / JSON。
4. 文件：\`open(path)\`、\`os.path.join\`（注意绝对路径覆盖前缀）、\`shutil.unpack_archive\`（Zip Slip）。
5. 模板：\`render_template_string(user)\`、Jinja2 \`Environment\` from_string、\`Markup\`。
6. SSRF：\`requests.get(url)\`、\`urllib\`、\`httpx\`、urllib3，参数来自请求。

## 3. Django 重点

1. \`DEBUG=True\` 生产开启 → 报错页泄露源码/配置。
2. \`ALLOWED_HOSTS=['*']\`、\`SECRET_KEY\` 硬编码在 settings。
3. \`CSRF\`：\`@csrf_exempt\` 装饰器滥用在这一类写接口上。
4. ORM 注入：\`.extra()\`、\`.raw()\`、\`RawSQL\`、\`Q(**{user_key: val})\`（字段名可控）。
5. 反序列化：session 用 pickle serializer、MessagePack、签名失效。

## 4. 判定、定级、误报

1. 不可信输入进入 sink 且无参数化/白名单/编码 → 漏洞。
2. 定级：RCE/任意文件/认证绕过 = critical；越权/SSRF 内网/存储型 XSS = high；受限 = medium。
3. 误报：常量来源、\`shell=False\` 数组调用、safe_load、参数化 ORM、已鉴权且归属校验。

## 5. 报告

每条给出：路径:行号、关键代码、source→sink 触发链、HTTP 原始请求 + curl PoC、修复建议（参数化/数组调用/safe_load/编码）。`

const PY_REF = `# Python 审计速查

## 危险函数 grep
- 命令：\`os.system\`、\`os.popen\`、\`subprocess.Popen\`、\`shell=True\`、\`commands.getoutput\`
- 反序列化：\`pickle.loads\`、\`pickle.load\`、\`yaml.load\`、\`marshal.loads\`、\`dill.loads\`
- 代码执行：\`eval\`、\`exec\`、\`compile\`、\`__import__\`、\`getattr(module, user)\`
- 文件：\`open(\`、\`os.path.join\`、\`shutil.unpack_archive\`、\`tarfile.extractall\`、\`zipfile.extractall\`
- SQL：\`.execute(\`、\`.raw(\`、\`.extra(\`、\`RawSQL\`、\`% (\` 拼接
- 模板：\`render_template_string\`、\`from_string\`、\`Environment(\`
- SSRF：\`requests.request\`、\`requests.get\`、\`urllib.request.urlopen\`、\`httpx.\`

## 框架识别
- Django：settings.py、urls.py、models.py、views.py、serializers
- Flask：app = Flask(__name__)、@app.route、Blueprint
- FastAPI：FastAPI()、@router、Depends、pydantic BaseModel（注意 Config extra='allow'）

## 常见缺陷
- FastAPI/DRF 宽松绑定（extra='allow' / fields='__all__'）→ 批量赋值。
- Jinja2 沙箱逃逸：Template(\`{{...}}\`) 用户可控。
- Celery 反序列化：\`task_serializer='pickle'\`。`

const NODE_METHODOLOGY = `## 0. 适用场景

用于 Node.js 后端（Express / Koa / Fastify / NestJS / Hapi）的系统化审计。以"原型链污染 + 命令执行 + SSRF + 模板"为中心，先建入口地图。

## 1. 入口枚举

1. 路由：express \`app.get/post\`、koa-router、fastify \`route\`、@nestjs 装饰器 \`@Controller/@Get\`。
2. 中间件：body-parser、cookie-parser、自定义 auth、CORS 配置。
3. 数据解析：\`req.query\`、\`req.body\`、\`req.params\`、\`req.headers\`、multipart、\`qs\` 解析。
4. 动态能力：\`eval\`、\`new Function\`、\`vm\`、模板引擎编译、\`require(user)\`。

## 2. 关键 sink 与卡点

1. 命令：\`child_process.exec(user)\`、\`execSync\`、\`spawn(user, {shell:true})\`。卡点：\`execFile\`、\`spawn\` 数组 + shell=false。
2. 原型链污染：\`lodash.merge/set/zipObjectDeep\`、\`Object.assign\` 深层、\`qs\`、自定义 deepMerge、\`obj[a][b]=v\` 递归赋值。接地 gadget：模板选项、\`child_process\` options、EJS 编译选项、\`Object.entries\` 遍历注入。
3. SQL/NoSQL：\`sequelize.query\` 拼接、\`knex.raw\`、mongoose \`$where\`、\`req.body\` 直接进查询。
4. SSRF：\`axios.get(req.query.url)\`、\`node-fetch\`、\`http.get\`、\`got\`。
5. 模板/代码：EJS \`<%- %>\`（未转义）、pug \`!{}\`、Handlebars \`{{{ }}}\`、\`eval\`、\`new Function\`。
6. 文件：\`fs.readFile(req.path)\`、\`path.join(root, userPath)\` 未 realpath 校验、\`send-file\` misuse。

## 3. 判定、定级、误报

1. 不可信输入进入危险 sink 且无参数化/白名单/转义/归属校验 → 漏洞。
2. 定级：RCE/原型链→RCE = critical；越权/SSRF 内网 = high；原型链仅篡改逻辑 = medium。
3. 误报：\`execFile\` 固定可执行 + 数组参数、使用 \`Object.create(null)\`、使用既有净化库且配置正确。

## 4. 报告

路径:行号、代码、source→sink 链、PoC（原始请求 + curl）、修复（execFile/白名单/DOMPurify/Object.freeze）。`

const NODE_REF = `# Node.js 审计速查

## 危险 API
- 命令：\`child_process.exec\`、\`execSync\`、\`spawn(..,{shell:true})\`、\`system\`
- 原型链：\`_.merge\`、\`_.set\`、\`_.zipObjectDeep\`、\`Object.assign\` 递归、\`qs.parse\`、\`JSON.parse\` 后 deepMerge
- 代码：\`eval\`、\`new Function\`、\`vm.runInNewContext\`、\`require(\` + 用户输入
- 模板：\`ejs.render\`、\`pug.render\`、\`handlebars.compile\`、\`nunjucks\`
- 文件：\`fs.readFile\`、\`fs.createReadStream\`、\`sendFile\`、\`path.join\`、\`path.resolve\`
- SSRF：\`axios\`、\`node-fetch\`、\`got\`、\`http.request\`

## 原型链污染要点
- 可控键 \`__proto__\` / \`constructor\` / \`prototype\` 是否被拦截。
- 污染后是否存在 gadget：模板引擎 \`settings\`/\`client\`、\`child_process\` 的 \`shell\`/\`env\`、Express 的 \`json spaces\`。
- 修复：\`Object.create(null)\`、合并前 hasOwnProperty + 键黑名单、禁用 \`__proto__\`。

## 框架识别
- Express: \`app.use\`、\`router\`
- NestJS: \`@Controller\`、\`@Get\`、\`class-validator\`、\`ValidationPipe\`（whitelist 是否开启，否则批量赋值）
- Fastify: \`fastify.route\`、schema 校验（缺失则无输入约束）`

const PHP_METHODOLOGY = `## 0. 适用场景

用于 PHP 应用（Laravel / Symfony / ThinkPHP / 原生 / WordPress 插件）的系统化审计。重点：文件包含、反序列化、命令执行、SQL、上传。

## 1. 入口枚举

1. 路由：Laravel \`routes/*.php\`、Symfony routing、ThinkPHP \`Route::\`、入口 index.php 的 \`$_GET/$_POST/$_REQUEST\`。
2. 数据解析：\`$_GET/$_POST/$_COOKIE/$_SERVER/$_FILES\`、\`php://input\`、\`json_decode(file_get_contents('php://input'))\`。
3. 动态能力：\`include/require\`、\`call_user_func\`、\`$$var\`、可变函数 \`$f()\`、\`assert\`、\`create_function\`、\`eval\`。

## 2. 关键 sink 与卡点

1. 命令：\`system\`、\`exec\`、\`shell_exec\`、\`passthru\`、\`popen\`、\`proc_open\`、反引号 \`\`\`cmd\`\`\`。卡点：\`escapeshellarg\` + \`escapeshellcmd\` 组合。
2. 代码：\`eval\`、\`assert\`（旧版可执行）、\`create_function\`、\`preg_replace /e\`（旧）。
3. 文件包含：\`include $user\`、\`require\`、模板 include；协议包装 \`php://filter\`、\`data://\`、\`expect://\`；\`allow_url_include\`。
4. 反序列化：\`unserialize($_user)\`、\`Phar\`（\`phar://\` 触发）、Session 反序列化、\`__wakeup/__destruct\` POP 链。
5. SQL：\`mysqli_query("..." . $_GET)\`、PDO \`query\` 拼接、\`->exec\` 拼接。卡点：PDO prepare + bindParam。
6. 上传：\`move_uploaded_file\` 仅校验扩展名、可传 .php/.phtml/.phar；存储目录可执行。
7. 文件操作：\`file_get_contents\`、\`fopen\`、\`readfile\`、\`unlink\` 路径可控。

## 3. 判定、定级、误报

1. 不可信输入进入 sink 且无转义/校验 → 漏洞。
2. 定级：RCE/任意文件包含/反序列化 RCE = critical；SQL 读写/上传 WebShell = high；受限 = medium。
3. 误报：escapeshellarg 且接收方逐个转义、PDO 参数化、路径来自常量。

## 4. 报告

路径:行号、代码、source→sink、PoC（原始请求 + curl / phar 触发说明）、修复（escapeshellarg、参数化、禁用 allow_url_include、反序列化白名单）。`

const PHP_REF = `# PHP 审计速查

## 危险函数
- 命令：system / exec / shell_exec / passthru / popen / proc_open / \`反引号\`
- 代码：eval / assert / create_function / preg_replace(.*/e)
- 包含：include / include_once / require / require_once
- 反序列化：unserialize / Phar (phar://) / __wakeup / __destruct
- 文件：file_get_contents / fopen / readfile / file_put_contents / unlink / copy
- SQL：mysqli_query / mysqli::query / PDO::query / ->exec / mysql_query

## 常见 POP 链依赖
- Monolog、Guzzle、Laravel（PendingBroadcast/Redis connection）、Symfony Process、Doctrine、ThinkPHP。

## PHP 配置相关
- \`allow_url_include=On\` -> 远程文件包含
- \`display_errors=On\` 生产 -> 信息泄露
- \`disable_functions\` 是否可被绕过（LD_PRELOAD/FFI）

## 框架识别
- Laravel: composer.json、\`Illuminate\`、\`app/Http/Controllers\`、middleware \`auth\`
- ThinkPHP: \`think\`、\`app/\`、\`route/\`
- Symfony: \`Symfony\\Component\`、控制器注解`

const GO_METHODOLOGY = `## 0. 适用场景

用于 Go 后端（Gin / Echo / Fiber / net/http / gRPC）的系统化审计。重点：命令注入、SQL、模板、SSRF、路径、反序列化（json/gob）。

## 1. 入口枚举

1. 路由：gin \`r.GET/POST\`、echo \`e.GET\`、fiber \`app.Get\`、net/http \`http.HandleFunc\`、gRPC service。
2. 数据解析：\`c.Query\`/\`c.Param\`/\`c.ShouldBind\`、\`r.URL.Query()\`、\`json.NewDecoder(r.Body)\`、\`mime/multipart\`。
3. 动态能力：\`os/exec\`、\`text/template\`、\`database/sql\` 拼接、\`plugin\`（Go 1.8+）。

## 2. 关键 sink 与卡点

1. 命令：\`exec.Command("sh","-c", user)\`、\`exec.Command(user)\`。卡点：\`exec.Command(name, args...)\` 不经过 shell。
2. SQL：\`db.Query("..." + x)\`、\`fmt.Sprintf("SELECT ... %s", x)\`、\`db.Raw\`。卡点：\`db.Query("WHERE id = ?", id)\` 占位符。
3. 模板：\`template.HTML(user)\`（绕过转义）、\`text/template\` 用于 HTML 输出、\`template.Must(...Parse(user))\`。
4. SSRF：\`http.Get(url)\`、\`http.Client.Do\`、\`net.Dial\`，URL 来自请求。
5. 路径：\`filepath.Join(root, user)\`（\`..\` 穿越）；\`os.Open\`；\`http.ServeFile\`。
6. 反序列化：\`encoding/gob.Decode\`（可构造）、\`json.Unmarshal\` 到 interface{}（有限）、yaml.v2/v3。

## 3. 判定、定级、误报

1. 不可信输入进入 sink 且无参数化/白名单/转义 → 漏洞。
2. 定级：命令 RCE/SQL 任意读写 = critical；SSRF 内网/越权 = high；受限 = medium。
3. 误报：\`exec.Command\` 固定命令 + 独立参数、SQL 占位符、\`html/template\` 自动转义。

## 4. 报告

路径:行号、代码、source→sink、PoC（原始请求 + curl）、修复（exec.Command 数组 / sql 占位符 / html/template / path 前缀校验）。`

const GO_REF = `# Go 审计速查

## 危险调用
- 命令：os/exec \`exec.Command\`、\`exec.CommandContext\`（检查是否含 sh -c）
- SQL：\`db.Query\`/\`db.Exec\`/\`db.QueryRow\` 拼接、\`fmt.Sprintf\` 进 SQL、\`db.Raw\`
- 模板：\`text/template\`、\`template.HTML\`、\`template.JS\`、\`template.URL\`
- SSRF：\`http.Get\`、\`http.Post\`、\`client.Do\`、\`net.Dial\`、\`net.DialTimeout\`
- 文件：\`os.Open\`、\`os.ReadFile\`、\`filepath.Join\`、\`http.ServeFile\`、\`os.Remove\`
- 反序列化：\`encoding/gob\`、\`yaml.Unmarshal\`（v2 危险默认）、\`json.Unmarshal\` 到 any

## 框架识别
- Gin: \`gin.Default()\`、\`c.ShouldBindJSON\`（binding tag 是否校验）
- Echo: \`echo.New()\`、\`c.Bind\`
- Fiber: \`fiber.New()\`、\`c.BodyParser\`

## 常见缺陷
- \`c.ShouldBind\` 绑定到含敏感字段的结构体 → 批量赋值（用 DTO）。
- \`template.HTML\` 直接包裹用户输入 → XSS。
- 目录遍历：\`filepath.Join\` 不清理 \`..\`，需 \`filepath.Clean\` + 前缀校验。`

const SSRF_DEEP = `## 0. 适用场景

针对 SSRF 单一漏洞家族的纵深审计：枚举所有出网请求点，逐个确认 URL 可控性与内网/元数据可达性。适用于"已知系统有 URL 抓取/回调/代理能力"的专项。

## 1. 出网请求点枚举（source）

1. 图片/头像抓取、URL 预览、网页截图、RSS/Feed 拉取、文件导入（导入外部 URL）。
2. Webhook 回调测试、远程配置/模板/规则拉取、Git/包仓库地址。
3. 代理/网关/转发、API 网关的 upstream、SOAP/XML 外部 DTD/实体。
4. 邮件签名验证、链接检测、短链展开、PDF/HTML 渲染（含外部资源）。

## 2. 危险协议与目标（sink）

1. 协议：\`file://\`、\`gopher://\`（可打 Redis/MySQL）、\`dict://\`、\`ftp://\`、\`ldap://\`、\`http(s)://\`。
2. 内网与元数据：127.0.0.0/8、10/8、172.16/12、192.168/16、169.254/16（\`169.254.169.254\` AWS/GCP/Azure/阿里云元数据）、\`::1\`、\`[::ffff:127.0.0.1]\`、\`0.0.0.0\`。
3. 绕过手法：十进制/八进制/十六进制 IP、\`@\` 混淆、DNS 重绑定、302 跳转、\`localhost.\` 结尾、短域名、IPv6 映射、URL 解析差异（后端与校验器不一致）。

## 3. 卡点确认（判定是否有漏洞的关键）

1. 协议白名单是否只允许 http/https。
2. 目标校验：是否在 DNS 解析后校验实际 IP（防重绑定）、是否跟随重定向到内网、是否校验每一跳。
3. 是否禁用重定向或对重定向再校验；是否能读取响应体回显（盲 SSRF vs 回显 SSRF）。
4. 出网权限：容器/主机是否有 egress 限制（可降低影响）。

## 4. 定级与误报

1. 可访问元数据/内网服务/内部 API = high/critical；仅可探测外网 = medium。
2. 误报：目标来自固定域名白名单 + 禁用重定向 + 解析后 IP 校验。

## 5. 报告

出网点路径:行号、URL 参数来源、可绕过的校验与协议、PoC（curl 直达内网/元数据）、修复（协议白名单 + DNS 解析后 IP 校验 + 禁重定向 + 独立出网代理）。`

const FILE_DEEP = `## 0. 适用场景

针对文件处理（上传/下载/解压/读写/包含）的专项纵深审计。覆盖任意文件读写、Zip Slip、上传 getshell、文件包含。

## 1. 文件相关入口枚举

1. 上传接口（multipart / base64 / chunk）、下载接口（filename / id / path 参数）。
2. 导入（CSV/XML/Excel/压缩包）、导出、模板文件、日志文件、临时文件。
3. 解压（zip/tar/gz）、文件预览、图片处理（缩略图、EXIF）、附件、头像。

## 2. 关键缺陷与 sink

1. 路径穿越：\`..\`、\`..\\\`、URL/双重编码、绝对路径、软链接、Windows 短文件名（\`PROGRA~1\`）、\`%\`00\` 截断（旧）。卡点：\`realpath\` 规范化后前缀校验。
2. Zip Slip：解压时每条目路径 \`../\` 逃逸；需对每个 entry 规范化并校验在目标目录内。
3. 上传 getshell：扩展名黑名单可绕过（\`.php5 .phtml .jspx .asa .pht\`）、大小写、双扩展名、\`%00\`、Content-Type/魔数校验缺失、存储目录可执行、可覆盖已存在文件（结合解析）。
4. 文件包含：\`include/require/template render\` 用户可控路径 + 协议包装。
5. 符号链接与竞态：先检查后使用（TOCTOU）、软链接指向敏感文件。
6. 文件读取回显：\`readfile/file_get_contents/send_file/ServeFile\` 用用户路径。

## 3. 判定、定级、误报

1. 可读写预期目录外文件、可上传并执行、可包含任意文件 → 漏洞。
2. 定级：任意文件读写/上传 WebShell/文件包含 RCE = critical/high；仅目录列举 = medium。
3. 误报：路径来自常量、规范化 + 根目录前缀校验、上传存对象存储且强制下载、白名单扩展名 + 内容校验。

## 4. 报告

路径:行号、代码、source→sink、PoC（上传 payload / 下载穿越 URL + curl）、修复（白名单 + realpath 前缀校验 + 重命名随机化 + 存储目录不可执行）。`

export const EXTRA_SKILLS = [
  {
    name: 'Python 应用审计方法论',
    category: '语言方法论',
    description:
      'Python 后端（Django/Flask/FastAPI/Celery）的系统化审计打法：入口枚举、sink 与卡点、Django 专项、判定定级与报告。用于 Python 项目的整体审计。',
    content: PY_METHODOLOGY,
    report_guide:
      '每条给出路径:行号 + 代码 + source→sink 触发链 + HTTP 原始请求/curl PoC + 修复；同根因合并并列出所有位置。',
    references: [{ path: 'references/python.md', content: PY_REF }],
  },
  {
    name: 'Node.js 应用审计方法论',
    category: '语言方法论',
    description:
      'Node.js 后端（Express/Koa/Fastify/NestJS）的系统化审计打法，以原型链污染、命令执行、SSRF、模板为中心，含框架识别与判定。',
    content: NODE_METHODOLOGY,
    report_guide:
      '每条给出路径:行号 + 代码 + source→sink 链 + 原始请求/curl PoC + 修复；原型链污染需说明接地 gadget 与可达性。',
    references: [{ path: 'references/node.md', content: NODE_REF }],
  },
  {
    name: 'PHP 应用审计方法论',
    category: '语言方法论',
    description:
      'PHP 应用（Laravel/ThinkPHP/Symfony/原生）的系统化审计打法：文件包含、反序列化 POP 链、命令执行、SQL、上传 getshell。',
    content: PHP_METHODOLOGY,
    report_guide:
      '每条给出路径:行号 + 代码 + source→sink + PoC（原始请求/curl 或 phar 触发说明）+ 修复建议。',
    references: [{ path: 'references/php.md', content: PHP_REF }],
  },
  {
    name: 'Go 应用审计方法论',
    category: '语言方法论',
    description:
      'Go 后端（Gin/Echo/Fiber/net-http/gRPC）的系统化审计打法：命令注入、SQL 拼接、模板、SSRF、路径穿越与反序列化。',
    content: GO_METHODOLOGY,
    report_guide:
      '每条给出路径:行号 + 代码 + source→sink + curl PoC + 修复（exec.Command 数组 / sql 占位符 / html-template / 路径前缀校验）。',
    references: [{ path: 'references/go.md', content: GO_REF }],
  },
  {
    name: 'SSRF 专项深度审计',
    category: '深度专项',
    description:
      '针对 SSRF 单一家族的纵深打法：出网请求点枚举、危险协议与内网/元数据目标、各类绕过手法、卡点确认与定级。',
    content: SSRF_DEEP,
    report_guide:
      '按「出网点(路径:行号) → URL 来源 → 可绕过校验/协议 → PoC(curl 直达内网/元数据) → 修复」组织。',
    references: [],
  },
  {
    name: '文件处理专项深度审计',
    category: '深度专项',
    description:
      '针对文件处理（上传/下载/解压/读写/包含）的专项纵深打法：路径穿越、Zip Slip、上传 getshell、文件包含、TOCTOU。',
    content: FILE_DEEP,
    report_guide:
      '分「任意文件读写 / Zip Slip / 上传 getshell / 文件包含」四类组织，每条给路径:行号 + PoC + 修复。',
    references: [],
  },
  {
    name: 'API 越权与访问控制专项',
    category: '深度专项',
    description:
      '针对 API 越权（水平/垂直/多租户）的专项纵深打法：逐个接口核对鉴权与对象归属、批量赋值、鉴权中间件绕过、越权测试矩阵。',
    content: `## 0. 适用场景

针对 REST/GraphQL API 的越权专项审计。越权是 API 最高频、最易漏的高危问题，值得单独一轮系统化核对。

## 1. 建立接口清单与鉴权矩阵

1. 枚举所有接口：OpenAPI/Swagger、路由文件、控制器注解、前端 API 客户端代码反推。
2. 为每个接口标注：是否登录、鉴权方式（Session/JWT/AK-SK/OAuth）、所需角色、目标对象的归属维度（user/tenant/org）。
3. 区分：读接口 / 写接口 / 管理接口 / 内部接口（RPC、actuator、定时任务触发）。

## 2. 水平越权（IDOR）核对

1. 每个读/写接口：是否只校验"已登录"，没有校验"请求对象是否属于当前用户/租户"（\`WHERE id=? AND user_id=?\`）。
2. 路径/参数中的 id、uid、orderId、tenantId、fileId 是否直接用于查询或操作，未与会话身份比对。
3. 先取对象再校验归属，还是先按 id 取再返回（后者默认越权）。
4. 批量/列表接口是否通过 filter 参数枚举他人数据（\`?userId=xxx\`）。

## 3. 垂直越权（功能级）

1. 管理/内部接口是否可达，是否二次鉴权（不能只靠前端隐藏入口）。
2. 角色校验是否只在前端/菜单级；后端是否统一中间件校验。
3. 鉴权中间件绕过：路径匹配差异（\`/admin\` vs \`/admin/\` vs \`/ADMIN\` vs \`/admin;.js\` vs \`/./admin\`）、静态资源规则误覆盖、大小写、URL 编码、\`X-Original-URL\`/\`X-Rewrite-URL\` 头。

## 4. 多租户与批量赋值

1. 租户维度是否在数据层强制注入，客户端可控 tenantId 是否被信任。
2. 批量赋值：请求体直接绑定实体，role/is_admin/ownerId/status/balance/price 可被提交篡改。

## 5. 判定、定级、误报

1. 未经授权身份可访问他人资源或执行无权操作 → 漏洞。
2. 定级：越权读写他人敏感数据 / 管理员操作可达 = critical/high；受限信息越权 = medium。
3. 误报：统一鉴权中间件 + 每个敏感接口显式对象归属校验 + DTO 白名单。

## 6. 报告

接口(方法+路径)、鉴权缺口、对象归属缺失点(路径:行号)、PoC（两个账号交叉请求的原始 HTTP + curl）、修复（统一鉴权中间件 + 归属校验 + DTO 白名单）。`,
    report_guide:
      '按接口列「鉴权矩阵 → 越权点(路径:行号) → 双账号交叉 PoC → 修复」；区分水平/垂直/多租户三类。',
    references: [],
  },
  {
    name: '代码审计通用流程与勘察',
    category: '方法论',
    description:
      '动手审计前的通用勘察流程：技术栈与框架识别、攻击面地图、共享安全边界定位、审计优先级排序、报告组织。任何项目先跑这套。',
    content: `## 0. 适用场景

任何代码库审计的**第一步**：在进行具体漏洞家族审计之前，先做勘察，产出"技术栈 + 攻击面地图 + 优先审计清单"。避免一上来就盲扫清单。

## 1. 技术栈与框架识别

1. 读清单文件：package.json / pom.xml / build.gradle / requirements.txt / go.mod / composer.json / Gemfile / *.csproj，确定语言、框架、关键依赖版本。
2. 读入口：main / index / app / Application / Startup / server，确认启动方式、端口、中间件注册顺序。
3. 读配置：application.yml / .env / config/*，确认数据源、外部集成、鉴权方式、调试开关。

## 2. 攻击面地图（source 清单）

1. 所有 HTTP 路由（含未文档化的、内部管理路由）。
2. 中间件与过滤器链：鉴权、参数解析、CORS、限流在哪一层。
3. 非 HTTP 入口：定时任务、消息消费者、Webhook、CLI、文件导入、gRPC。
4. 前端可见接口（从静态资源 / API client 反推）。

## 3. 共享安全边界定位（最高优先级）

1. 统一鉴权/授权中间件：一处缺陷影响全部接口。
2. 全局输入过滤 / 参数绑定 / SQL 工具类 / 加解密工具 / 模板渲染封装 / 文件工具类。
3. 这些"公共组件"是审计重点——先审它们，再顺着调用点扩散。

## 4. 危险 API 全量 grep（建候选池）

- 命令、SQL、反序列化、模板、文件、SSRF、上传、XXE、加密、日志——各用 grep 拉全量候选（宁可多列，再逐一排除）。

## 5. 审计优先级排序

1. 先审可达的高危 sink（RCE/越权/任意文件/反序列化）。
2. 再审共享边界组件的缺陷（影响面大）。
3. 最后补配置类、信息泄露类。

## 6. 报告组织

1. 开头：技术栈、攻击面地图、已覆盖与未覆盖范围。
2. 主体：按严重级别排序的发现（路径:行号 + 代码 + source→sink + PoC + 修复）。
3. 结尾：整体风险判断、横向影响说明、后续建议。`,
    report_guide:
      '报告分「勘察结论(技术栈+攻击面地图+共享边界) → 按级别排序的发现 → 覆盖说明与后续建议」。',
    references: [],
  },
]
