## **写在前面：**

最近有一个想法，做一个程序员师徒管理系统。因为在大学期间的我在学习java的时候非常地迷茫，找不到自己的方向，也没有一个社会上有经验的前辈去指导，所以走了很多的弯路。后来工作了，想把自己的避坑经验分享给别人，但是发现身边都是有经验的开发者，也没有机会去分享自己的想法，所以富贵同学就想做一个程序员专属的师徒系统，秉承着徒弟能够有人指教少走弯路，师傅能桃李满天下的目的，所以开始做这个师徒系统，也会同步更新该系统所用到的技术，并且作为教程分享给大家，希望大家能够关注一波。
![请添加图片描述](https://img-blog.csdnimg.cn/93ce07a15e6c4ed2a125e4bd2d194e52.jpg)
好的，接下来给大家讲一讲改系统中安全模块用到的技术：JWT，用SpringBoot整合JWT。
## 第一步，导入jar包

```clike
     <!--JWT-->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>
        <dependency><!--解决：java.lang.ClassNotFoundException: javax.xml.bind.DatatypeConverter -->
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.3.0</version>
        </dependency>
        <!--JWT-->
```
这里我们用的是`jjwt`，为什么不用原生的`jwt`呢？我们来认识一下`jjwt`：
***JJWT可以理解为jwt的框架***

- JJWT是一个提供端到端的JWT创建和验证的Java库。永远免费和开源(Apache License，版本2.0)，JJWT很容易使用和理解。它被设计成一个以建筑为中心的流畅界面，隐藏了它的大部分复杂性。

- JJWT的目标是最容易使用和理解用于在JVM上创建和验证JSON Web令牌(JWTs)的库。

- JJWT是基于JWT、JWS、JWE、JWK和JWA RFC规范的Java实现。

- JJWT还添加了一些不属于规范的便利扩展，比如JWT压缩和索赔强制。

大家导包的时候记得一定要导入jaxb-api这个包，否则就会在创建`jwt token`的时候报错，这都是富贵同学照着网上教程弄下来踩过的坑。
![请添加图片描述](https://img-blog.csdnimg.cn/c1b3922a53e445808a8009d24f93fbae.jpg)
接下来我们需要`springsecurity`作为安全框架来使用jwt所以我们还需要导入springsecurity的包：

```clike
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
```

## 第二步，编写我们的工具类来管理`jwt token`

```java
public class JwtTokenUtils {

    public static final String TOKEN_HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";

    private static final String SECRET = "jwt";
    private static final String ISS = "echisan";

    // 角色的key
    private static final String ROLE_CLAIMS = "rol";

    // 过期时间是3600秒，既是1个小时
    private static final long EXPIRATION = 3600L;

    // 选择了记住我之后的过期时间为7天
    private static final long EXPIRATION_REMEMBER = 604800L;


    // 创建token
    public static String createToken(String username, String role, boolean isRememberMe) {
        long expiration = isRememberMe ? EXPIRATION_REMEMBER : EXPIRATION;
        HashMap<String, Object> map = new HashMap<>();
        map.put(ROLE_CLAIMS, role);

        return Jwts.builder()
                .signWith(SignatureAlgorithm.HS256, SECRET.getBytes(StandardCharsets.UTF_8))
                .setClaims(map)
                .setIssuer(ISS)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expiration * 1000))
                .compact();


    }


    // 从token中获取用户名
    public static String getUsername(String token) {
        return getTokenBody(token).getSubject();
    }

    // 获取用户角色
    public static String getUserRole(String token) {
        return (String) getTokenBody(token).get(ROLE_CLAIMS);
    }

    // 是否已过期
    public static boolean isExpiration(String token) {
        try {
            return getTokenBody(token).getExpiration().before(new Date());
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    private static Claims getTokenBody(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET.getBytes(StandardCharsets.UTF_8))
                .parseClaimsJws(token)
                .getBody();
    }
}

```
这个类其实很简单，不过就是产生token和获取用户信息。
这里大家要注意了，因为jwt是一串经过特殊编码可存储用户信息的字符串，所以大家不要将敏感信息存到jwt中，怎么存？看上面工具类中的`createToken（）`方法，比如说`setSubject（）`这个方法就能够将用户的姓名存储到jwt的字符串中，这些都可以通过反编码技术反编译出来的，所以大家注意。

现在我们的工具类有了，我们需要用jwt来代替springsecurity来管理用户的token，所以我们应该想到的是在`WebSecurityConfigurerAdapter`类中来配置jwt的过滤类：

```java

@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private CustomUserDetailsService userDatailService;

    /**
     * anyRequest          |   匹配所有请求路径
     * access              |   SpringEl表达式结果为true时可以访问
     * anonymous           |   匿名可以访问
     * denyAll             |   用户不能访问
     * fullyAuthenticated  |   用户完全认证可以访问（非remember-me下自动登录）
     * hasAnyAuthority     |   如果有参数，参数表示权限，则其中任何一个权限可以访问
     * hasAnyRole          |   如果有参数，参数表示角色，则其中任何一个角色可以访问
     * hasAuthority        |   如果有参数，参数表示权限，则其权限可以访问
     * hasIpAddress        |   如果有参数，参数表示IP地址，如果用户IP和参数匹配，则可以访问
     * hasRole             |   如果有参数，参数表示角色，则其角色可以访问
     * permitAll           |   用户可以任意访问
     * rememberMe          |   允许通过remember-me登录的用户访问
     * authenticated       |   用户登录后可访问
     */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // post请求要关闭csrf验证,不然访问报错；实际开发中开启，需要前端配合传递其他参数
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/swagger-ui.html").anonymous()
                .antMatchers("/swagger-resources/**").anonymous()
                .antMatchers("/webjars/**").anonymous()
                .antMatchers("/*/api-docs").anonymous()
                //放开注册,登录用户接口
                .antMatchers("/user/register").anonymous()
                .antMatchers("/user/login").anonymous()
                .anyRequest().authenticated() // 所有请求都需要验证
                .and()
                .formLogin() // 使用默认的登录页面
                .and()
                //添加用户账号的认证
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                //添加用户权限的认证
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                //添加没有携带token或者token无效操作
                .authenticationEntryPoint(new JWTAuthenticationEntryPoint())
                //添加无权限时的处理
                .accessDeniedHandler(new JWTAccessDeniedHandler());
    }

    /**
     * 指定加密方式
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // 使用BCrypt加密密码
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                // 从数据库读取的用户进行身份认证
                .userDetailsService(userDatailService)
                .passwordEncoder(passwordEncoder());
    }
//    @Override
//    protected void configure(HttpSecurity httpSecurity) throws Exception{
//        //调试阶段
//        httpSecurity.csrf().disable().authorizeRequests();
//        httpSecurity.authorizeRequests().anyRequest()
//                .permitAll().and().logout().permitAll();
//    }


}
```
在这个方法中：

```java
                //添加用户账号的认证
                .addFilter(new JWTAuthenticationFilter(authenticationManager()))
                //添加用户权限的认证
                .addFilter(new JWTAuthorizationFilter(authenticationManager()))
```
这样配置之后就可以编写jwt的认证类和授权类来了代理springsecurity来管理用户的认证和授权了：

```java
/**
 * 用户账号的验证
 * JWTAuthenticationFilter继承于UsernamePasswordAuthenticationFilter 该拦截器用于获取用户登录的信息，只需创建一个token并调用
 * authenticationManager.authenticate()让spring-security去进行验证就可以了，不用自己查数据库再对比密码了，这一步交给spring去操作。
 * 这个操作有点像是shiro的subject.login(new UsernamePasswordToken())
 * Created by Mrfugui 2021年10月30日10:53:30
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private ThreadLocal<Integer> rememberMe = new ThreadLocal<>();
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        //这里特别注意是登录的接口，自定义登录接口，不写的话默认"/login"
        super.setFilterProcessesUrl("/auth/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws AuthenticationException {

        // 从输入流中获取到登录的信息
        try {
            LoginUser loginUser = new ObjectMapper().readValue(request.getInputStream(), LoginUser.class);
            rememberMe.set(loginUser.getRememberMe() == null ? 0 : loginUser.getRememberMe());
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginUser.getUsername(), loginUser.getPassword(), new ArrayList<>())
            );
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    // 成功验证后调用的方法
    // 如果验证成功，就生成token并返回
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
                                            HttpServletResponse response,
                                            FilterChain chain,
                                            Authentication authResult) {

        JwtUser jwtUser = (JwtUser) authResult.getPrincipal();
        System.out.println("jwtUser:" + jwtUser.toString());
        boolean isRemember = rememberMe.get() == 1;

        String role = "";
        Collection<? extends GrantedAuthority> authorities = jwtUser.getAuthorities();
        for (GrantedAuthority authority : authorities){
            role = authority.getAuthority();
        }

        String token = JwtTokenUtils.createToken(jwtUser.getUsername(), role, isRemember);
        // 返回创建成功的token
        // 但是这里创建的token只是单纯的token
        // 按照jwt的规定，最后请求的时候应该是 `Bearer token`
        response.setHeader("Authorization", JwtTokenUtils.TOKEN_PREFIX + token);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.getWriter().write(JSONObject.toJSONString(ResponseUtils.msg(failed.getMessage())));
    }
}

```

```java

/**
 * 验证成功当然就是进行鉴权了，每一次需要权限的请求都需要检查该用户是否有该权限去操作该资源，当然这也是框架帮我们做的，那么我们需要做什么呢？
 * 很简单，只要告诉spring-security该用户是否已登录，是什么角色，拥有什么权限就可以了。
 * JWTAuthenticationFilter继承于BasicAuthenticationFilter，至于为什么要继承这个我也不太清楚了，这个我也是网上看到的其中一种实现，
 * 实在springSecurity苦手，不过我觉得不继承这个也没事呢（实现以下filter接口或者继承其他filter实现子类也可以吧）只要确保过滤器的顺序，
 * JWTAuthorizationFilter在JWTAuthenticationFilter后面就没问题了。
 * Created by MrFugui 2021年10月30日10:53:44
 */
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws IOException, ServletException {

        String tokenHeader = request.getHeader(JwtTokenUtils.TOKEN_HEADER);
        // 如果请求头中没有Authorization信息则直接放行了
        if (tokenHeader == null || !tokenHeader.startsWith(JwtTokenUtils.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            return;
        }
        // 如果请求头中有token，则进行解析，并且设置认证信息
        try {
            SecurityContextHolder.getContext().setAuthentication(getAuthentication(tokenHeader));
        } catch (TokenIsExpiredException e) {
            //返回json形式的错误信息
            response.setCharacterEncoding("UTF-8");
            response.setContentType("application/json; charset=utf-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write(JSONObject.toJSONString(ResponseUtils.msg(e.getMessage())));
            response.getWriter().flush();
            return;
        }
        super.doFilterInternal(request, response, chain);
    }

    // 这里从token中获取用户信息并新建一个token
    private UsernamePasswordAuthenticationToken getAuthentication(String tokenHeader) throws TokenIsExpiredException {
        String token = tokenHeader.replace(JwtTokenUtils.TOKEN_PREFIX, "");
        boolean expiration = JwtTokenUtils.isExpiration(token);
        if (expiration) {
            throw new TokenIsExpiredException("token超时了");
        } else {
            String username = JwtTokenUtils.getUsername(token);
            String role = JwtTokenUtils.getUserRole(token);
            if (username != null) {
                return new UsernamePasswordAuthenticationToken(username, null,
                        Collections.singleton(new SimpleGrantedAuthority(role))
                );
            }
        }
        return null;
    }
}

```
这个两个类是控制用户认证授权成功之后的方法，但是有一个点请大家特别注意：

```java
   //这里特别注意是登录的接口，自定义登录接口，不写的话默认"/login"
        super.setFilterProcessesUrl("/auth/login");
```
但是这个时候又两个认证授权类还不够，我们还需要处理用户没有token的情况：

```java
.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling()
                //添加没有携带token或者token无效操作
                .authenticationEntryPoint(new JWTAuthenticationEntryPoint())
                //添加无权限时的处理
                .accessDeniedHandler(new JWTAccessDeniedHandler());
```
第一句的意思是：
我们可以准确地控制什么时机创建session，有以下选项进行控制：
//always – 如果session不存在总是需要创建；
//ifRequired – 仅当需要时，创建session(默认配置)；
//never – 框架从不创建session，但如果已经存在，会使用该session ；
//stateless – Spring Security不会创建session，或使用session；
***所以我们还需要两个类：***     `JWTAuthenticationEntryPoint 和        JWTAccessDeniedHandler`
注意他们的顺序，不要搞反：


```java
/**
 * 没有携带token或者token无效
 * @author MrFugui 2021年10月30日10:55:21
 */
public class JWTAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException exception) throws IOException, ServletException {

        String result = "";
        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType("application/json;charset=UTF-8");
        if (exception instanceof BadCredentialsException || exception instanceof InternalAuthenticationServiceException) {
            response.setStatus(HttpStatus.BAD_REQUEST.value());
            result = JSONObject.toJSONString(ResponseUtils.msg(CodeEnums.PASSWORD_ERROR.getMsg()));
        } else if (exception instanceof InsufficientAuthenticationException
                || exception instanceof NonceExpiredException) {
            result = JSONObject.toJSONString(ResponseUtils.msg(CodeEnums.AUTH_ERROR.getMsg()));
        } else if (exception instanceof UsernameNotFoundException) {
            result = JSONObject.toJSONString(ResponseUtils.msg(CodeEnums.NO_USER.getMsg()));
        } else {
            result = "系统异常。";
        }
        response.getWriter().write(result);
    }
}

```

```java
/**
 * @author MrFugui
 * 2021年10月30日10:54:20
 * @description:没有访问权限
 */
public class JWTAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AccessDeniedException e) throws IOException, ServletException {
        httpServletResponse.setCharacterEncoding("UTF-8");
        httpServletResponse.setContentType("application/json; charset=utf-8");
        httpServletResponse.setStatus(HttpServletResponse.SC_FORBIDDEN);
        httpServletResponse.getWriter().write(JSONObject.toJSONString(ResponseUtils.msg(e.getMessage())));
    }
}

```
好了到了这里我们的`jwt`就集合springboot完成了，这个时候我们通过postman返回登录接口获得token之后就可以访问我们的接口了
注意：该博客里面的代码需要大家去码云仓库中去获取，仓库地址[Gitee-JWT](https://gitee.com/WangFuGui-Ma/spring-boot-jwt)
## 说在之后
师徒系统我会一直更新，因为是开源的项目，所以我也希望又更多的小伙伴加入进来！！
这是程序员师徒管理系统的地址：
[程序员师徒管理系统](https://gitee.com/WangFuGui-Ma/Programmer-Apprentice)
![在这里插入图片描述](https://img-blog.csdnimg.cn/23eefccf438f4aaeb5a143f1db1f0fa7.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBAY3NkbmVyTQ==,size_16,color_FFFFFF,t_70,g_se,x_16)
