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
]
