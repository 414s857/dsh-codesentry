/** Built-in vulnerability audit prompts. Each one is scoped to a single class. */
export const BUILTIN_PROMPTS = [
  {
    name: 'SQL 注入',
    category: '注入',
    default_severity: 'critical',
    content: `审计目标：找出所有可被外部输入影响并进入 SQL 语句执行的路径。
检查清单：
1. 拼接字符串构造 SQL 的位置（字符串模板、+ 拼接、StringBuilder、动态表名/列名）。
2. ORM / MyBatis / JPA 中使用 \${...}、字符串拼接、原生查询的参数拼接。
3. 存储过程、动态 ORDER BY、LIMIT、LIKE、IN 子句等无法参数化的位置是否做了白名单校验。
4. 输入是否来自 HTTP 参数、Header、Cookie、消息队列、文件、数据库等不可信来源。
5. 二次注入：写入数据库后又拼接回 SQL 的数据。
判定标准：不可信输入未经过参数化绑定或严格白名单就进入 SQL 语法位置，才判定为漏洞。
误报排除：仅使用预编译参数、或拼接值来自常量/可信枚举。
严重级别：可直接读取或写入任意数据为 critical；仅影响查询条件为 high；受限场景为 medium。
对应 CWE：CWE-89（SQL 注入）、二次注入 CWE-89 / CWE-915。`,
  },
  {
    name: '跨站脚本 XSS',
    category: '注入',
    default_severity: 'high',
    content: `审计目标：找出不可信输入未经过编码就进入 HTML / DOM / JavaScript 上下文的路径。
检查清单：
1. 服务端模板：未转义输出（innerHTML、document.write、dangerouslySetInnerHTML、v-html、th:utext 等）。
2. 前端富文本渲染、Markdown 渲染是否关闭了 HTML 过滤。
3. URL / href / src / style / event handler 等属性上下文是否做了对应编码与协议校验（javascript:）。
4. 反射型、存储型、DOM 型（location.hash、document.referrer、postMessage）三条路径都要覆盖。
5. CSP 与 HttpOnly 只能降低影响，不能替代输出编码。
判定标准：不可信数据进入可执行上下文且没有上下文相关的编码/净化。
误报排除：使用了成熟净化库（如 DOMPurify）且配置正确，或输出经过严格白名单。
严重级别：存储型且影响已登录用户为 high/critical；反射型为 medium/high；纯 DOM 型为 medium。
对应 CWE：CWE-79（XSS）；DOM 型 CWE-79。`,
  },
  {
    name: '命令注入与代码执行',
    category: '注入',
    default_severity: 'critical',
    content: `审计目标：找出不可信输入进入系统命令、Shell、进程参数或动态代码执行的位置。
检查清单：
1. Runtime.exec / ProcessBuilder / subprocess / os.system / exec / system() / popen 的调用。
2. 命令字符串拼接、shell=True、未转义参数、PowerShell 脚本拼接。
3. eval / Function / execScript / 反序列化表达式 / 模板引擎执行任意表达式。
4. 文件路径、URL、压缩包、日志内容等间接进入命令的路径。
5. 检查是否存在参数白名单、命令固定、输入转义或最小权限隔离。
判定标准：不可信输入能改变命令结构或执行任意代码。
误报排除：exec 接收固定命令且参数以数组传递并经过校验。
严重级别：可执行任意命令或代码为 critical。
对应 CWE：CWE-78（OS 命令注入）、CWE-77、CWE-94（代码注入）、CWE-95（eval 注入）。`,
  },
  {
    name: '路径穿越与任意文件读写',
    category: '文件',
    default_severity: 'high',
    content: `审计目标：找出不可信输入可控制文件路径并突破预期目录的位置。
检查清单：
1. 文件下载、上传、读取、删除、解压接口中的路径参数。
2. 是否仅使用字符串 replace("../")，是否处理 ..\\、URL 编码、绝对路径、软链接、Windows 短文件名。
3. 规范化后是否校验了 realpath 与允许根目录的前缀关系。
4. 压缩包解压（Zip Slip）是否校验每个条目路径。
5. 临时文件、日志文件、配置文件写入路径是否可被控制。
判定标准：可以读取或写入预期目录之外的文件。
误报排除：路径来自服务端常量，或规范化后严格限制在允许目录内。
严重级别：任意文件读写为 high/critical；仅可列举目录为 medium。
对应 CWE：CWE-22（路径穿越）、CWE-23、CWE-36；Zip Slip 为 CWE-22。`,
  },
  {
    name: '不安全的反序列化',
    category: '反序列化',
    default_severity: 'critical',
    content: `审计目标：找出不可信数据进入反序列化或对象绑定过程的位置。
检查清单：
1. Java ObjectInputStream、readObject、XStream、Fastjson autoType、Jackson 多态类型、Hessian、Kryo。
2. .NET BinaryFormatter / TypeNameHandling，PHP unserialize，Python pickle / yaml.load。
3. 反序列化前的类型白名单、类加载器限制、签名校验是否存在。
4. 序列化数据是否可被外部请求、Cookie、缓存、MQ 消息控制。
判定标准：不可信输入进入可触发任意类型构造或代码执行的反序列化入口。
误报排除：使用安全格式（JSON 且关闭多态）、或配置了严格类型白名单。
严重级别：可 RCE 为 critical。
对应 CWE：CWE-502（不可信数据反序列化）。`,
  },
  {
    name: '认证与会话缺陷',
    category: '认证',
    default_severity: 'high',
    content: `审计目标：找出认证绕过、会话固定、弱令牌与权限提升问题。
检查清单：
1. 登录、注册、找回密码、验证码校验、OAuth / SSO 回调的完整流程。
2. 会话令牌生成是否使用安全随机数，是否可预测、是否在 URL 中传递、是否缺少轮换。
3. JWT：算法混淆（none/HS256 与公钥混用）、签名校验缺失、过期时间与吊销机制。
4. 越权：接口是否只校验登录而不校验对象归属（IDOR）、管理接口是否可达。
5. 密码重置令牌是否一次性、是否有有效期、是否绑定用户。
判定标准：可以不经过预期认证流程获得身份或更高权限。
误报排除：存在统一鉴权中间件且对象归属被显式校验。
严重级别：认证绕过或管理员越权为 critical；普通水平越权为 high；会话加固缺失为 medium。
对应 CWE：认证绕过 CWE-287/CWE-306、会话固定 CWE-384、JWT 算法混淆 CWE-347、越权/CWE-639/CWE-284。`,
  },
  {
    name: '服务端请求伪造 SSRF',
    category: '网络',
    default_severity: 'high',
    content: `审计目标：找出服务端使用不可信地址发起请求的位置。
检查清单：
1. Webhook、图片抓取、URL 预览、文件导入、代理、远程配置拉取。
2. 协议限制：是否允许 file://、gopher://、dict://、ftp://。
3. 内网地址校验：127.0.0.0/8、10/8、172.16/12、192.168/16、169.254/16、::1、元数据地址 169.254.169.254。
4. 重定向跟随、DNS 重绑定、IPv6 与十进制/八进制 IP 绕过。
5. 出网权限与响应内容回显程度。
判定标准：不可信输入可控制请求目标地址。
误报排除：目标域名白名单固定且禁用了重定向。
严重级别：可访问云元数据或内网服务为 high/critical；仅可探测外网为 medium。
对应 CWE：CWE-918（SSRF）。`,
  },
  {
    name: '硬编码凭据与敏感信息泄露',
    category: '配置',
    default_severity: 'high',
    content: `审计目标：找出代码、配置、日志中泄露的密钥与敏感数据。
检查清单：
1. 硬编码的数据库密码、API Key、AK/SK、JWT 签名密钥、私钥、证书口令。
2. 默认账号密码、调试开关、Swagger / Actuator / 管理后台未授权暴露。
3. 日志或异常响应中打印令牌、身份证、手机号、完整请求体。
4. .env、配置文件、CI 配置中的明文密钥，以及提交历史中的泄露。
5. 加密密钥与数据存放在同一位置，或使用弱随机数生成密钥。
判定标准：凭据或敏感信息以明文形式存在于可读取的代码/配置/日志中并可被利用。
误报排除：明确的示例值、测试用假密钥、已吊销的空值。
严重级别：生产可用凭据为 critical/high；调试信息泄露为 medium。
对应 CWE：硬编码凭据 CWE-798、敏感信息泄露 CWE-200/CWE-312（明文存储）。`,
  },
  {
    name: '加密与随机数缺陷',
    category: '加密',
    default_severity: 'medium',
    content: `审计目标：找出错误的密码学用法。
检查清单：
1. 已淘汰算法：MD5、SHA1、DES、3DES、RC4、ECB 模式、无 IV 的 CBC。
2. 使用 Math.random / Random / rand() 生成令牌、验证码、密钥。
3. IV / Salt 固定或可预测，密钥派生未使用 PBKDF2/scrypt/Argon2。
4. 加密后未做完整性校验（无 MAC / AEAD），或自实现加密协议。
5. 证书校验被关闭（trustAll、verify=false、HostnameVerifier 返回 true）。
判定标准：加密原语或参数选择使机密性/完整性目标无法达成。
误报排除：仅用于非安全场景的校验和、或明确兼容旧数据的只读解密路径。
严重级别：签名密钥或会话令牌可预测为 high；弱哈希用于密码存储为 high；一般算法降级为 medium。
对应 CWE：弱算法 CWE-327、弱随机数 CWE-338/CWE-330、证书校验缺失 CWE-295、缺少完整性 CWE-353。`,
  },
  {
    name: '文件上传与 XXE',
    category: '文件',
    default_severity: 'high',
    content: `审计目标：找出文件上传校验缺失与 XML 外部实体注入。
检查清单：
1. 上传：扩展名、Content-Type、文件头魔数校验，是否可上传脚本/HTML/SVG，存储目录是否可执行。
2. 文件名是否可控制（路径穿越）、是否重命名、是否随机化。
3. 图片处理库是否可被恶意图片触发漏洞，压缩包是否限制大小与数量。
4. XML 解析器是否禁用 DOCTYPE、外部实体、外部 DTD（XXE），是否使用安全配置。
5. 上传后的文件访问是否带 Content-Disposition 与正确 Content-Type。
判定标准：可上传可执行/可解析文件并产生影响，或 XML 可读取本地文件/发起内网请求。
误报排除：上传文件存对象存储且强制下载，或 XML 解析器已禁用外部实体。
严重级别：上传 WebShell 或 XXE 读取敏感文件为 critical/high；受限上传为 medium。
对应 CWE：不受限上传 CWE-434、XXE CWE-611。`,
  },
  {
    name: '竞态与业务逻辑',
    category: '业务逻辑',
    default_severity: 'medium',
    content: `审计目标：找出并发条件下的状态不一致与可绕过的业务约束。
检查清单：
1. 余额、库存、优惠券、积分、提现、下单等"检查—扣减"之间的时间窗口。
2. 幂等性缺失导致重复提交、重复领取、重复退款。
3. 数据库事务隔离级别、行锁/悲观锁/乐观锁、分布式锁是否正确使用。
4. 价格、数量、角色、状态等关键字段是否由客户端提交并可篡改。
5. 审批、支付回调、签名校验是否可伪造或重放。
判定标准：并发或重放能够获得超出业务规则的利益或破坏数据一致性。
误报排除：存在数据库唯一约束/原子更新/幂等键等可靠防护。
严重级别：直接资金损失为 critical/high；状态不一致为 medium。
对应 CWE：竞态 CWE-362/CWE-367（TOCTOU）、业务逻辑/参数篡改 CWE-840、缺少幂等 CWE-837。`,
  },
  {
    name: '依赖与供应链风险',
    category: '依赖',
    default_severity: 'medium',
    content: `审计目标：找出可被利用的第三方依赖与供应链问题。
检查清单：
1. 依赖清单中已知高危版本（反序列化、日志、模板、文件上传、鉴权组件）。
2. 依赖是否锁定版本、是否存在可被投毒的非官方源或私有仓库配置。
3. 构建脚本、postinstall、动态下载二进制的行为。
4. 反序列化/表达式/解析类库的默认配置是否安全。
5. 是否引入来源不明或长期未维护的组件。
判定标准：依赖的已知漏洞或配置可在本项目可达路径中被触发。
误报排除：漏洞代码路径不可达，或已有缓解措施。
严重级别：可达 RCE 为 critical/high；信息泄露为 medium；仅版本过旧为 low。
对应 CWE：CWE-1104（使用未维护/有漏洞组件）、CWE-1395（依赖脆弱组件）、CWE-829（引入不可信功能）。`,
  },
  {
    name: '模板注入与表达式注入',
    category: '注入',
    default_severity: 'critical',
    content: `审计目标：找出不可信输入进入模板引擎、表达式引擎或 EL/SpEL/OGNL 求值的位置。
检查清单：
1. 服务端模板引擎（Jinja2、Twig、Freemarker、Velocity、Thymeleaf）是否使用动态模板内容或字符串拼接模板。
2. Spring EL、OGNL、MVEL、Groovy、JavaScript 引擎（Nashorn/GraalJS）的求值入口。
3. 用户输入进入模板变量时是否仍会被当作模板语法解析（二次渲染）。
4. 是否开启沙箱、是否限制了危险类与方法访问。
5. 前端模板编译（客户端模板）是否把用户输入当作模板源码。
判定标准：不可信输入能改变模板/表达式结构并被服务端执行。
误报排除：仅作为模板数据变量传入且引擎默认转义，或使用固定模板。
严重级别：可执行任意表达式或命令为 critical；仅可读取上下文变量为 medium/high。
对应 CWE：SSTI CWE-1336、表达式语言注入 CWE-917、代码注入 CWE-94。`,
  },
  {
    name: '日志、异常与信息泄露',
    category: '配置',
    default_severity: 'low',
    content: `审计目标：找出通过错误信息、日志、调试接口泄露的内部信息。
检查清单：
1. 异常堆栈直接返回给客户端、详细 SQL 错误、内网地址与框架版本。
2. 日志记录完整令牌、密码、Cookie、个人敏感信息。
3. 调试端点、健康检查、指标接口暴露内部状态且无鉴权。
4. 目录列表、备份文件、.git、.svn、编辑器临时文件可访问。
5. 响应头泄露服务器版本、缺少安全响应头。
判定标准：泄露的信息可辅助攻击者进一步利用系统。
误报排除：仅返回通用错误码，且日志已脱敏。
严重级别：可获取凭据或内网拓扑为 medium/high；一般信息泄露为 low。
对应 CWE：CWE-209（异常信息泄露）、CWE-532（日志泄露敏感信息）、CWE-200（信息暴露）、CWE-548（目录列表）。`,
  },
  {
    name: '访问控制与越权（IDOR / 批量赋值）',
    category: '访问控制',
    default_severity: 'critical',
    content: `审计目标：找出授权边界缺失导致的可访问他人数据或越权操作。
检查清单：
1. 逐个写操作与读接口核对：是否只校验"已登录"，而没有校验"请求对象属于当前用户/租户/组织"（IDOR、水平越权）。
2. 路径/参数中的 id、uid、orderId、tenantId 等是否直接用于查询，未与当前会话身份做归属比对。
3. 管理/内部接口是否可达、是否二次鉴权（垂直越权）；是否存在仅靠前端隐藏按钮伪装的后端无鉴权。
4. 批量赋值（Mass Assignment）：请求体/表单字段是否直接绑定到实体，role、is_admin、balance、price、status、ownerId 可被客户端提交篡改。
5. 权限模型是否统一集中在鉴权中间件；找出绕过中间件的路由（路径匹配绕过、静态资源、actuator、内部 RPC）。
判定标准：未经授权的身份可以访问本无权访问的资源或执行本无权执行的操作。
误报排除：存在统一鉴权中间件且每个敏感接口都显式校验了对象归属。
严重级别：越权读写他人数据或管理员操作可达为 critical/high；受限信息越权为 medium。
对应 CWE：CWE-639（IDOR）、CWE-284（访问控制不当）、CWE-285、CWE-862（缺少授权）、CWE-915（批量赋值）。`,
  },
  {
    name: '跨站请求伪造 CSRF',
    category: '访问控制',
    default_severity: 'high',
    content: `审计目标：找出可被第三方站点诱导发起、携带用户身份的有状态写请求。
检查清单：
1. 所有会改变状态的接口（改密、改邮箱、转账、下单、加白名单、绑卡、授权 OAuth）是否缺少 CSRF 防护。
2. 防护方式是否有效：Anti-CSRF Token 是否随请求校验、是否绑定会话、是否可预测/复用；SameSite Cookie 设置；Origin/Referer 校验。
3. GET 请求是否被用于执行写操作（本应 POST）。
4. JSON / multipart 接口是否以为"必须是 application/json"就免防护（表单跨域仍可发简单请求，或被 CORS 放宽）。
5. 关键操作是否二次验证（密码、验证码、MFA）。
判定标准：攻击者无需受害者交互即可让受害者浏览器携带其凭据完成敏感操作。
误报排除：使用严格 SameSite=Lax/Strict + Token 校验 + Origin 校验之一且覆盖所有写接口。
严重级别：改密/转账/授权类为 high/critical；低影响状态变更为 medium。
对应 CWE：CWE-352（CSRF）。`,
  },
  {
    name: '开放重定向与 URL 信任',
    category: '网络',
    default_severity: 'medium',
    content: `审计目标：找出用不可信参数决定跳转目标或加载远程资源的位置。
检查清单：
1. 登录成功、登出、支付回跳、短链、OAuth redirect_uri 等处的 next/url/return/target 参数直接跳转。
2. 跳转目标是否做了白名单校验（域名、协议、主机精确匹配），还是仅用 startsWith/contains 判断（可被 //evil、@、.evil.com 绕过）。
3. 是否允许 javascript:/data:/file: 等危险协议。
4. 服务端根据参数加载远程模板、远程配置、远程脚本、回调地址（不仅跳转，还包括"信任外部 URL 内容"）。
5. OAuth 授权码模式下 redirect_uri 是否严格匹配注册值。
判定标准：不可信输入可把用户导向攻击者站点或让服务端加载不可信内容。
误报排除：目标来自固定常量或严格白名单。
严重级别：OAuth redirect_uri 可控为 high；一般开放重定向为 medium（常作钓鱼/令牌窃取链）。
对应 CWE：CWE-601（开放重定向）、CWE-939（OAuth redirect_uri 不当）。`,
  },
  {
    name: 'HTTP 请求走私与响应拆分',
    category: '网络',
    default_severity: 'high',
    content: `审计目标：找出前端代理与后端对 HTTP 报文边界解析不一致、或响应头注入的位置。
检查清单：
1. 是否存在反代/CDN（Nginx、HAProxy、Envoy）与后端对 Content-Length、Transfer-Encoding 处理不一致（CL.TE、TE.CL、TE.TE）。
2. 前端是否直接透传客户端 Content-Length / Transfer-Encoding 双头；是否允许被篡改的畸形头。
3. 响应头构造是否拼接用户输入（CRLF 注入 \r\n）导致响应拆分 / 头注入 / 缓存投毒。
4. 是否对请求行、Host 头做严格校验（Host 头注入影响缓存与重置链接）。
5. 请求体长度、分块编码、重复头字段的处理是否一致。
判定标准：攻击者可构造歧义请求使后端解析出额外请求或被注入响应头。
误报排除：单一同构代理、无用户可控头部拼接。
严重级别：可达成请求走私/缓存投毒为 high/critical；仅响应头 CRLF 注入为 medium/high。
对应 CWE：CWE-444（请求走私）、CWE-113（响应拆分/CRLF 注入）、CWE-644（Host 头不当）。`,
  },
  {
    name: '原型链污染 Prototype Pollution',
    category: '注入',
    default_severity: 'high',
    content: `审计目标：找出把不可信输入合并进对象、污染 Object.prototype 的位置（Node/JS 栈重点）。
检查清单：
1. 深层合并/赋值：lodash.merge / mergeWith / set / zipObjectDeep、Object.assign 深层实现、自定义 deepMerge。
2. 查询字符串/body 解析：qs、querystring、express.json 对 __proto__、constructor.prototype 的处理。
3. 是否存在递归按路径赋值（\`obj[path[0]][path[1]] = val\`），未拦截 __proto__/constructor/prototype 键。
4. 污染后的"接地"（gadget）：模板引擎选项、child_process 的 shell 选项、配置合并、Object.entries 遍历中的属性注入。
5. 使用 Map、Object.create(null) 或冻结原型可降低影响。
判定标准：可控键值能写入 Object.prototype 并影响后续对象行为。
误报排除：合并前做了 hasOwnProperty + key 黑名单，或使用无原型的对象存储。
严重级别：可链式达成 RCE（如影响 child_process）为 critical/high；仅属性篡改影响逻辑为 medium。
对应 CWE：CWE-1321（原型链污染）。`,
  },
  {
    name: '客户端安全与前端存储',
    category: '客户端',
    default_severity: 'medium',
    content: `审计目标：找出前端在浏览器侧暴露的信任边界问题。
检查清单：
1. 敏感令牌（access/refresh token、API Key）是否存放在 localStorage/sessionStorage 且可被 XSS 读取；是否应改用 HttpOnly Cookie。
2. postMessage：是否校验 event.origin 与 event.source，是否把消息内容当作 HTML/代码执行（window.postMessage 通配 "*"）。
3. 前端路由/菜单级权限控制是否被误当作安全边界（后端未校验）。
4. CSP 是否缺失或存在 unsafe-inline/unsafe-eval、过宽 script-src；是否可被绕过。
5. 前端硬编码的后端地址、密钥、内部接口；调试开关、source map 是否暴露。
判定标准：浏览器侧可读取或伪造敏感数据/操作，或把不可信内容当作代码执行。
误报排除：令牌存 HttpOnly Cookie、postMessage 严格校验 origin、CSP 有效且严格。
严重级别：可窃取令牌或达成 XSS 链为 high；一般配置缺失为 low/medium。
对应 CWE：CWE-922（敏感信息不安全存储）、CWE-346（Origin 校验缺失）、CWE-1021、CWE-693（CSP 保护不当）。`,
  },
  {
    name: '内存安全与原生代码缺陷',
    category: '内存安全',
    default_severity: 'high',
    content: `审计目标：找出 C/C++/Rust(unsafe)/Go(unsafe) 等原生代码中的内存与整数缺陷（仅当审计目标含原生代码时启用）。
检查清单：
1. 缓冲区操作：strcpy/strcat/sprintf/gets/memcpy/memmove 的长度来源是否可控、是否校验目标容量。
2. 整数：长度/偏移计算中的溢出、回绕、符号有无转换（int <- size_t）导致分配与拷贝长度不一致。
3. 释放后使用（UAF）、双重释放、悬垂指针、未初始化读取。
4. 越界读/写：数组与切片下标来自外部输入、off-by-one、循环边界。
5. 格式化字符串（printf 参数可控）、命令/路径拼接用的缓冲区。
判定标准：外部可控输入可导致内存越界、破坏或任意读写。
误报排除：使用安全封装（如 snprintf 且校验返回值）且长度有界。
严重级别：可远程触发的栈/堆溢出或 UAF 为 critical/high；本地或受限为 medium。
对应 CWE：CWE-120（缓冲区溢出）、CWE-122（堆溢出）、CWE-190（整数溢出）、CWE-416（UAF）、CWE-415（双重释放）、CWE-134（格式化字符串）。`,
  },
  {
    name: 'NoSQL / LDAP / 其他注入',
    category: '注入',
    default_severity: 'high',
    content: `审计目标：找出非 SQL 的查询/目录/表达式注入（NoSQL、LDAP、XPath、Log 注入等）。
检查清单：
1. NoSQL：MongoDB 查询把用户对象/字符串直接传入（\`{ $where: user }\`、\`$ne\`、\`$gt\` 操作符被注入，如 \`{"username": {"$ne": null}}\`）、JS 求值 \`$where\`/\$function。
2. LDAP：查询过滤器拼接用户输入未转义（\`*(uid=*)\`），可绕过认证或枚举。
3. XPath / XML 查询拼接。
4. 日志注入：用户输入写入日志导致伪造日志行、CRLF 注入。
5. 命令行/IPC 参数注入（非 shell 但由参数语义导致，如 git 参数注入）。
判定标准：不可信输入改变了查询/过滤器语义并可绕过条件或读取额外数据。
误报排除：所有值都经类型约束（如强制为字符串并转义）或用参数化查询对象。
严重级别：认证绕过或任意数据读取为 high/critical；受限为 medium。
对应 CWE：NoSQL 注入 CWE-943、LDAP 注入 CWE-90、XPath 注入 CWE-643、日志注入 CWE-117。`,
  },
  {
    name: "GraphQL 安全",
    category: "接口",
    default_severity: "high",
    content: `审计目标：找出 GraphQL 接口的注入、越权、信息暴露与拒绝服务问题。
检查清单：
1. 内省（__schema / introspection）是否在生产开放，暴露全部类型与字段。
2. 字段级授权：是否只在校验 resolver 参数而无对象层/字段级归属校验（可越权读取他人数据）。
3. 通过嵌套/别名/片段对同一查询做批量放大（别名爆破、深层嵌套、循环片段）导致资源耗尽。
4. 查询深度/复杂度/批量数是否限流；是否禁用或限制 batching（一次请求多查询）。
5. 参数进入 SQL / NoSQL / 命令 / 模板等下游 sink 时是否仍参数化；GraphQL 不等于自动安全。
判定标准：不可信查询能越权访问数据、触发下游注入或造成可控资源耗尽。
误报排除：生产关闭内省、有深度/复杂度限制、字段级鉴权完整、resolver 层已参数化。
严重级别：越权读取敏感数据为 high/critical；无限制 DoS 为 medium/high；仅内省暴露为 low。
对应 CWE：CWE-284（访问控制不当）、CWE-770（资源分配无限制）、CWE-943（查询语义注入）。`,
  },
  {
    name: "WebSocket 与实时通信安全",
    category: "网络",
    default_severity: "high",
    content: `审计目标：找出 WebSocket / SSE / 长连接通道上的鉴权、来源校验与消息信任缺陷。
检查清单：
1. 握手阶段的鉴权：是否在 upgrade 之前校验会话/令牌，还是任意连接都可建立（跨站 WebSocket 劫持）。
2. Origin 校验：是否校验 Origin 头，防止恶意页面借用户 Cookie 建立连接。
3. 消息信任：服务端是否把收到的消息当作已认证用户的可信指令（未绑定连接与用户身份），可出现客户端伪造 userId/role。
4. 消息进入下游 sink（SQL、命令、广播模板、反序列化）时是否校验与编码。
5. 广播/订阅的频道鉴权：是否允许订阅他人频道、消息是否越权投递。
判定标准：可在未授权或不属己的上下文中收发消息、冒用身份或注入下游。
误报排除：握手强制鉴权、Origin 白名单、消息与连接身份强绑定、频道级鉴权完整。
严重级别：身份冒用/越权数据为 high/critical；仅 Origin 缺失为 medium。
对应 CWE：CWE-1385（跨站 WebSocket 劫持）、CWE-306（缺少鉴权）、CWE-284。`,
  },
  {
    name: "JWT 与会话令牌安全",
    category: "认证",
    default_severity: "high",
    content: `审计目标：找出 JWT / 签名令牌在生成、校验、传递全链路上的缺陷。
检查清单：
1. 算法混淆：是否信任令牌头 alg（none、HS256 用公钥当 HMAC 密钥、RS/HS 混用）、是否固定期望算法。
2. 签名密钥：是否硬编码/弱密钥/可枚举，是否与业务密钥复用。
3. 校验缺失：是否只解码不验签、是否忽略 exp/nbf/iat、是否忽略 aud/iss。
4. 存储与传递：是否放在 URL、localStorage（可被 XSS 读取）、日志中；是否可被重放（无 jti/吊销机制）。
5. kid 头：是否用 kid 拼接文件路径或 SQL（kid 注入）；jku/x5u 是否加载外部密钥 URL（SSRF/密钥劫持）。
判定标准：可伪造/篡改令牌获得他人或更高身份，或令牌被泄露/可重放。
误报排除：算法固定、密钥来自安全随机、全字段校验、短期有效+可吊销。
严重级别：可伪造任意身份为 critical；弱密钥/可重放为 high；存储不当为 medium。
对应 CWE：CWE-347（签名校验不当）、CWE-345（来源真实性不足）、CWE-798（硬编码凭据）、CWE-613（会话过期不足）。`,
  },
  {
    name: "XXE 与 XML 解析安全",
    category: "文件",
    default_severity: "high",
    content: `审计目标：找出 XML 解析器未禁用外部实体、外部 DTD 与危险扩展的位置。
检查清单：
1. 解析入口：DocumentBuilderFactory、SAXParserFactory、XMLInputFactory、XMLReader、libxml/SimpleXML、Python xml.etree/lxml、.NET XmlReader/XmlDocument。
2. 是否显式禁用：disallow-doctype-decl、external-general-entities、external-parameter-entities、LOAD_EXTERNAL_DTD、XMLConstants.FEATURE_SECURE_PROCESSING。
3. 是否允许 XInclude、是否解析用户上传/SOAP/配置的 XML。
4. 盲 XXE：即使不回显，是否可通过外部 DTD 造成 SSRF、文件探测、OOB 数据外带（DNS/HTTP 回连）。
5. 是否接受用户可控的 XSLT / 外部样式表（XSLT 可执行代码）。
判定标准：XML 可读取本地文件、发起内网请求或触发 OOB 外带。
误报排除：解析器已关闭 DOCTYPE 与外部实体、输入为可信内部数据。
严重级别：读敏感文件/SSRF 内网为 critical/high；仅可探测为 medium。
对应 CWE：CWE-611（XXE）、CWE-776（DTD 实体膨胀/Billion Laughs）、CWE-918（SSRF）。`,
  },
  {
    name: "HTTP 安全头与传输安全",
    category: "配置",
    default_severity: "low",
    content: `审计目标：找出缺失的安全响应头、不安全的传输与 Cookie 配置。
检查清单：
1. 传输：是否强制 HTTPS、是否启用 HSTS（含 preload/subDomains）、是否存在混合内容、TLS 是否使用弱协议/套件。
2. 响应头：CSP（是否缺失或含 unsafe-inline/unsafe-eval/过宽）、X-Content-Type-Options、X-Frame-Options/frame-ancestors、Referrer-Policy、Permissions-Policy。
3. Cookie：是否设置 Secure、HttpOnly、SameSite；作用域 Domain/Path 是否过宽；是否在子域间共享。
4. CORS：Access-Control-Allow-Origin 是否为 * 或反射 Origin 而 Allow-Credentials=true（跨域读敏感数据）。
5. 缓存：敏感响应是否缺少 Cache-Control: no-store，是否被共享缓存缓存。
判定标准：缺失的控制使攻击者可实施降级、点击劫持、跨域读取、窃取 Cookie 或缓存敏感数据。
误报排除：已有等效控制（如 CSP 通过 frame-ancestors 覆盖）、纯内部无浏览器场景。
严重级别：CORS 反射 Origin+凭据为 high；缺失 HSTS/安全头为 low/medium；Cookie 缺 HttpOnly/Secure 为 medium。
对应 CWE：CWE-693（保护机制失效）、CWE-1021（点击劫持）、CWE-942（CORS 过宽）、CWE-614（Cookie 缺 Secure）、CWE-319（明文传输）。`,
  },
  {
    name: "敏感文件、备份与目录暴露",
    category: "配置",
    default_severity: "medium",
    content: `审计目标：找出可被直接访问的敏感静态资源、备份、版本库与调试产物。
检查清单：
1. 版本控制与 IDE：.git/、.svn/、.hg/、.idea/、.vscode/、.DS_Store 可访问。
2. 备份与临时：*.bak、*.old、*.swp、*~、*.sql、*.zip、*.tar.gz、数据库文件、日志文件。
3. 配置与密钥：.env、config.*、application.yml、web.config、id_rsa、*.pem、credentials 的 Web 可访问性。
4. 目录列表：静态目录开启 autoindex/Index of，可枚举文件。
5. 构建产物：source map（.map）暴露源码、Swagger/Actuator/phpinfo/调试页面可访问。
判定标准：上述文件可通过 HTTP 直接下载并含敏感信息或可辅助进一步利用。
误报排除：返回 403/404、文件已脱敏、仅含公开示例数据。
严重级别：泄露凭据/源码/数据库为 high/critical；目录列表/调试信息为 medium；仅冗余静态资源为 low。
对应 CWE：CWE-538（文件与目录暴露）、CWE-548（目录列表）、CWE-527（版本库暴露）、CWE-540（源码泄露）。`,
  },
  {
    name: "数据完整性与不安全传输",
    category: "加密",
    default_severity: "medium",
    content: `审计目标：找出缺少完整性保护、可被篡改或明文传输的敏感数据。
检查清单：
1. 加密无认证：使用 CBC/CTR 等非 AEAD 模式却无 MAC，可被位翻转/填充预言攻击。
2. 序列化/令牌无签名：Cookie、隐藏字段、URL 参数承载状态却未加签（如 role=admin 明文）。
3. 下载/更新无校验：客户端更新包、远程配置、插件是否校验签名或哈希，是否可被中间人替换。
4. 明文传输：敏感数据通过 HTTP、FTP、明文邮件或未加密消息队列传输。
5. 哈希用于完整性却用弱算法（MD5/SHA1）或长度扩展可绕过。
判定标准：可篡改受保护数据而不被发现，或敏感数据可被截获。
误报排除：使用 AEAD（GCM/ChaCha20-Poly1305）、HMAC 覆盖、全链路 TLS 且证书校验开启。
严重级别：可篡改授权/支付/更新为 high/critical；一般完整性缺失为 medium。
对应 CWE：CWE-353（缺少完整性校验）、CWE-345（真实性不足）、CWE-319（明文传输）、CWE-347。`,
  },
  {
    name: "日志注入与不安全日志实践",
    category: "配置",
    default_severity: "low",
    content: `审计目标：找出用户输入写入日志导致伪造/污染，以及日志泄露敏感信息的问题。
检查清单：
1. 日志注入：用户输入（UA、参数、文件名、Header）未清洗写入日志，含 CRLF 可伪造日志行、污染 SIEM/审计。
2. 敏感信息入日志：令牌、密码、完整身份证/银行卡、Cookie、完整请求体被记录。
3. 日志文件本身可被 Web 访问或权限过宽（world-readable）。
4. 日志内容进入下游（日志分析、ELK、Splunk）时是否被当作可信数据执行/渲染（存储型注入）。
5. 审计日志是否可被用户删除/篡改（缺少完整性、可绕过的日志级别）。
判定标准：可伪造/污染审计记录、或以明文形式泄露敏感信息。
误报排除：日志脱敏、结构化日志转义换行、访问控制严格。
严重级别：可篡改审计/泄露凭据为 medium/high；一般日志注入为 low。
对应 CWE：CWE-117（日志注入）、CWE-532（日志泄露敏感信息）、CWE-778（日志不足）。`,
  },
  {
    name: "文件包含与动态加载",
    category: "文件",
    default_severity: "high",
    content: `审计目标：找出用不可信输入决定加载/包含/require 的文件或模块的位置。
检查清单：
1. 本地/远程文件包含：include/require/import（PHP）、模板 include、动态 import、LoadLibrary/dlopen、Class.forName。
2. 是否允许协议包装器（php://filter、php://input、data://、expect://）或远程 URL 加载。
3. 路径是否可穿越到系统文件或上传目录；是否拼接用户输入。
4. 动态类加载/反射：用户可控类名/方法名（Class.forName、BeanShell）；模块加载路径可写目录。
5. 反序列化/配置加载器（SnakeYAML、yaml.load、pickle）是否可从不可信路径加载。
判定标准：不可信输入可改变被包含/加载的文件或模块，导致读源码、执行代码或加载恶意模块。
误报排除：包含路径来自白名单常量、无用户可控成分。
严重级别：可包含任意文件或加载任意代码为 critical/high；仅可读受限文件为 medium。
对应 CWE：CWE-98（PHP 文件包含）、CWE-829（引入不可信功能）、CWE-470（不安全反射）、CWE-706。`,
  },
  {
    name: "多租户隔离与数据边界",
    category: "访问控制",
    default_severity: "critical",
    content: `审计目标：找出 SaaS/多租户系统中租户数据未隔离、可跨租户访问的问题。
检查清单：
1. 所有查询是否强制带 tenant_id/org_id 条件，还是依赖当前会话注入；是否存在缺条件的查询。
2. tenant 标识是否来自客户端可控参数（Header、Body、子域）而未与登录态绑定。
3. 缓存键、队列 topic、文件存储路径、对象存储前缀是否含租户维度，避免串号。
4. 后台/管理员/导出/批处理任务是否跨租户泄漏数据；报表聚合是否越界。
5. 软删除与回收站、备份、搜索索引是否隔离租户。
判定标准：可通过参数/身份横移到其他租户读取或写入数据。
误报排除：租户维度在数据层强制（RLS/中间件统一注入）且无法被客户端覆盖。
严重级别：跨租户读写数据为 critical；隔离不完整但受限为 high。
对应 CWE：CWE-639（IDOR）、CWE-284（访问控制不当）、CWE-566（授权绕过）。`,
  },
  {
    name: "批量赋值与参数篡改",
    category: "访问控制",
    default_severity: "high",
    content: `审计目标：找出请求参数可直接绑定到实体/模型，从而篡改敏感字段的问题。
检查清单：
1. 框架自动绑定：Spring @ModelAttribute、Jackson/Rails strong params 缺失、Django ModelForm fields='__all__'、Laravel fillable 未设。
2. 敏感字段是否可被提交：role、is_admin、is_staff、balance、credit、price、status、ownerId、tenantId、verified、permissions。
3. 只读/派生字段、内部字段是否被暴露到请求契约。
4. 更新接口是否“取请求体整对象 save”，而非仅更新允许的字段。
5. 是否存在 DTO 与实体分离、白名单字段映射。
判定标准：客户端可提交业务上不应由用户控制的字段并获得利益或提权。
误报排除：使用显式字段白名单 DTO、敏感字段服务端强制覆盖。
严重级别：提权/资金篡改为 critical/high；状态误导为 medium。
对应 CWE：CWE-915（批量赋值）、CWE-639、CWE-840（业务逻辑）。`,
  },
  {
    name: "缓存投毒与缓存欺骗",
    category: "网络",
    default_severity: "medium",
    content: `审计目标：找出 CDN/反向代理/应用缓存把不可信或错误内容缓存给其他用户的问题。
检查清单：
1. 缓存键是否包含所有影响响应的输入（Header、Cookie、扩展名、查询参数）；是否存在 unkeyed input（X-Forwarded-Host、X-Original-URL、部分 Cookie）。
2. Web 缓存欺骗：路径后缀（/profile.css、/a.js）使 CDN 缓存动态敏感页，被他人读取。
3. Host 头/绝对 URL 注入是否被缓存（影响密码重置链接、重定向、脚本 src）。
4. Cache-Control/Vary 缺失导致个性化响应被公共缓存。
5. 缓存键规范化差异（大小写、编解码、分号参数、末尾斜杠）导致的绕过。
判定标准：攻击者可让缓存向他人返回攻击者构造或他人私有的内容。
误报排除：缓存键完整、Vary 正确、敏感响应 no-store、无未键控输入。
严重级别：缓存欺骗读取他人数据为 high；一般投毒为 medium。
对应 CWE：CWE-525（Web 缓存信息泄露）、CWE-444（请求走私相关）、CWE-644（Host 头不当）。`,
  },
  {
    name: "拒绝服务与资源耗尽",
    category: "业务逻辑",
    default_severity: "medium",
    content: `审计目标：找出可被低成本放大的资源耗尽、算法复杂度过高与无限制操作。
检查清单：
1. 正则灾难性回溯（ReDoS）：用户可控字符串进入复杂正则（嵌套量词）。
2. 无限制上传大小/数量、无分页上限的列表查询、无速率限制的昂贵接口（导出、报表、图片处理、邮件发送）。
3. XXE/解压/JSON 深层嵌套（深度炸弹）、超大 XML（Billion Laughs）导致内存/CPU 耗尽。
4. 密码哈希/加密参数可被操纵（bcrypt 成本来自请求）、批处理可被无限触发。
5. 连接池/线程/队列耗尽：长耗时操作占满资源。
判定标准：单个或少量请求即可显著消耗资源、影响可用性。
误报排除：有大小/速率/复杂度上限与超时、隔离执行。
严重级别：可稳定拖垮服务为 high；局部放大为 medium。
对应 CWE：CWE-400（资源消耗不受控）、CWE-1333（ReDoS）、CWE-770（分配无限制）、CWE-776。`,
  },
  {
    name: "CI/CD 与构建脚本安全",
    category: "依赖",
    default_severity: "high",
    content: `审计目标：找出流水线、构建钩子与部署脚本中的注入与密钥泄露。
检查清单：
1. 注入：不可信输入（PR 标题、分支名、issue 内容、commit message）进入 shell/run 步骤；GitHub Actions 的 github.event.* 上下文拼接进 run。
2. 权限：工作流 token 权限过宽（write-all）、pull_request_target 触发外部代码、自托管 runner 被不可信提交执行。
3. 密钥：CI 变量是否可能被打印、是否通过环境暴露给不可信步骤、是否可被 fork PR 读取。
4. 依赖与制品：构建是否拉取未签名/可被投毒的依赖或镜像，缓存投毒。
5. postinstall/prepare 脚本、Makefile、Dockerfile 中的动态下载与 curl|bash。
判定标准：外部可控输入可执行任意命令或窃取 CI 密钥/制品。
误报排除：输入经严格校验/引号转义、权限最小化、无不可信触发。
严重级别：可执行命令/窃取密钥为 critical/high；配置不当为 medium。
对应 CWE：CWE-78（命令注入）、CWE-829（引入不可信功能）、CWE-522（凭据保护不足）、CWE-94。`,
  },
  {
    name: "数据库与存储层安全",
    category: "配置",
    default_severity: "high",
    content: `审计目标：找出数据存储层配置与访问控制缺陷（非注入类）。
检查清单：
1. 凭据与网络：数据库默认/弱口令、监听 0.0.0.0、无 TLS、未加 IP 白名单、端口对公网暴露。
2. 权限：应用账号是否过度授权（DDL/多库/root），读写账号是否分离。
3. 对象存储（S3/OSS/MinIO）：Bucket 是否 public、ACL 过宽、预签名 URL 有效期过长或无鉴权、路径可枚举。
4. 数据保护：是否需要加密的敏感列明文存储、备份文件可下载、无行级/列级访问控制。
5. 缓存（Redis/Memcached）：未鉴权、可公网访问、绑定地址过宽。
判定标准：可直接访问或越权读写存储数据，或凭据/配置暴露。
误报排除：仅内网+白名单+强口令+最小权限。
严重级别：公网可写/可读敏感数据为 critical/high；配置弱化为 medium。
对应 CWE：CWE-306（缺少鉴权）、CWE-798、CWE-521（弱口令）、CWE-284、CWE-1188（默认配置不安全）。`,
  },
  {
    name: "开放端口与服务指纹暴露",
    category: "配置",
    default_severity: "medium",
    content: `审计目标：找出代码/配置中暴露的可利用内部服务与调试端口。
检查清单：
1. 生产启用的调试/管理端口：JVM debug（5005）、JMX、Actuator、admin、profiler、php-fpm status。
2. 暴露的中间件：Redis、MongoDB、Elasticsearch、RabbitMQ、etcd、Docker API（2375）、Kubernetes API 无鉴权。
3. 硬件/监控/运维接口（prometheus、grafana、jenkins）弱口令或匿名访问。
4. 服务指纹：版本响应头、错误页框架版本，是否暴露已知 CVE 的版本。
5. 绑定地址：是否监听 0.0.0.0 而非 127.0.0.1/内网。
判定标准：可从外部触达本应内部的服务，且存在弱鉴权或无鉴权。
误报排除：仅内网可达、已鉴权、非生产环境。
严重级别：无鉴权可达 RCE/数据（Docker API、Redis）为 critical/high；仅指纹暴露为 low。
对应 CWE：CWE-306（缺少鉴权）、CWE-1188（默认配置不安全）、CWE-200（信息暴露）、CWE-16（配置）。`,
  },
  {
    name: "业务逻辑与流程绕过",
    category: "业务逻辑",
    default_severity: "high",
    content: `审计目标：找出可绕过业务约束、滥用流程获取不当利益的问题。
检查清单：
1. 顺序绕过：跳过前序步骤（未支付下单、跳过 KYC、跳过验证）直接进入后续状态。
2. 数量/额度：负数、超大值、边界值（0、-1、int 溢出）绕过金额/数量校验；负数退款。
3. 优惠券/积分/邀请：重复领取、自邀、叠加、条件伪造、时间窗口绕过。
4. 状态机：非法状态跳转（已取消订单再支付、已退款再退）、并发状态竞争。
5. 权限相关流程：审批流自批、越级审批、密保问题/找回流程可绕过。
判定标准：可完成业务上不允许的操作或获取超出规则的利益。
误报排除：服务端对每一步做完整状态与金额校验、有权威数据源。
严重级别：直接资金/权益损失为 critical/high；状态不一致为 medium。
对应 CWE：CWE-840（业务逻辑错误）、CWE-841（行为顺序不当）、CWE-20（输入校验不足）。`,
  },
  {
    name: "文件与目录权限、命令执行上下文",
    category: "配置",
    default_severity: "medium",
    content: `审计目标：找出文件权限过宽、以过高权限运行与不安全临时文件问题。
检查清单：
1. 上传/写入的文件权限是否 world-writable/executable；目录是否允许执行脚本。
2. 服务以 root/Administrator 运行，或子进程继承过高权限；SUID/capabilities 不当。
3. 临时文件：可预测名（/tmp/fixed）、竞态（先创建后写入）、符号链接跟随导致覆盖敏感文件。
4. 日志/配置/密钥文件权限允许其他用户读取。
5. 容器：以 root 运行、特权模式、挂载 docker.sock、敏感宿主路径挂载。
判定标准：权限配置使本地低权限用户或远程上传可提权、覆盖文件或执行命令。
误报排除：最小权限、文件权限受限、临时文件用安全随机名+O_EXCL。
严重级别：可提权/覆盖敏感文件为 high；一般权限松为 medium/low。
对应 CWE：CWE-732（权限分配不当）、CWE-250（过高权限执行）、CWE-377（不安全临时文件）、CWE-59（链接跟随）。`,
  },
  {
    name: "第三方集成与 Webhook 安全",
    category: "网络",
    default_severity: "high",
    content: `审计目标：找出对外集成（回调、Webhook、OAuth、支付、邮件/短信）的信任与签名缺陷。
检查清单：
1. Webhook 接收：是否校验来源签名（HMAC、时间戳防重放）、是否可被伪造事件触发内部动作。
2. OAuth 集成：state 参数是否校验（CSRF）、redirect_uri 严格匹配、token 交换是否校验 audience/scope。
3. 支付回调：是否验签、金额/订单号是否与本地订单校验、是否可重放或伪造成功。
4. 出站调用：第三方返回值是否被当作可信（注入到本地 SQL/模板/命令），是否校验 TLS 证书。
5. 邮件/短信：发信人可控、模板注入、配额滥用、开放中继。
判定标准：可伪造第三方事件、绕过签名或利用外部返回数据达成注入/越权。
误报排除：严格验签+时间戳窗口+幂等、外部数据均视为不可信并转义。
严重级别：可伪造支付/事件触发敏感操作为 critical/high；集成配置弱为 medium。
对应 CWE：CWE-345（真实性不足）、CWE-347、CWE-352（CSRF）、CWE-918（SSRF）、CWE-601。`,
  },
  {
    name: "信息泄露与侧信道",
    category: "配置",
    default_severity: "medium",
    content: `审计目标：找出可推断敏感信息的响应差异、枚举与侧信道。
检查清单：
1. 用户枚举：登录/注册/找回接口通过不同提示（“用户不存在”vs“密码错误”）或响应时间差异暴露账号存在性。
2. 时序侧信道：字符串比较、令牌校验用非常量时间比较（== 而非 constant-time）。
3. 响应差异：不同权限/存在性返回不同状态码、长度、错误码，可被推断。
4. 错误信息：堆栈、SQL 错误、内网 IP、版本号泄露。
5. 资源枚举：自增 ID、可预测的分享链接/邀请码、目录/文件可枚举。
判定标准：通过响应内容、状态或时间差异可推断出本不应得知的敏感信息。
误报排除：统一通用响应、常量时间比较、限流+验证码。
严重级别：可枚举账号/凭证推断为 medium/high；一般信息泄露为 low。
对应 CWE：CWE-203（可观察差异）、CWE-208（可观察时序差异）、CWE-204（响应差异）、CWE-200（信息暴露）。`,
  },
]
