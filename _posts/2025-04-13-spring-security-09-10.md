---
title: "[스프링 시큐리티 인 액션] 9장 - 10장"
date: YYYY-MM-DD HH:MM:SS +09:00
categories: []
tags:
  []
---
# 9장 - 필터 구현

HTTP 필터는 HTTP 요청에 적용되는 다양한 책임을 위임한다. 

스프링 시큐리티의 HTTP 필터는 일반적으로 요청에 적용해야 하는 각 책임을 관리하며 책임의 체인을 형성한다. 

스프링 시큐리티가 제공하는 필터 외의 맞춤형 필터를 필터 체인에 추가할 수 있다.

## 9.1 스프링 시큐리티 아키텍처의 필터 구현

### Filter

스프링 시큐리티 아키텍처의 필터는 일반적인 HTTP 필터다. 필터를 구현하려면 `javax.servlet` 의 `Filter` 인터페이스를 구현한다. 다른 HTTP 필터와 마찬가지로 `doFilter()` 메서드를 오버라이딩 해야한다.

```scss
public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
	// do something before the rest of the application
    chain.doFilter(request, response); // invoke the rest of the application
    // do something after the rest of the application
}
```

- ServletRequest - HTTP 요청으로 요청에 대한 세부 정보를 얻는다.
- ServletResponse - HTTP 응답으로 필터 체인에서 응답을 변경할 수 있다.
- FilterChain - 필터 체인을 나타낸다. 체인의 다음 필터로 요청을 전달한다.

### Filter Chain

필터가 작동하는 순서가 정의된 필터의 모음을 나타낸다. 

- BasicAuthenticationFilter - HTTP Basic 인증을 처리, `http.httpBasic()` 을 호출할 때만 포함됨
- CsrfFilter - CSRF 처리
- CorsFilter - CORS 권한 부여 규칙 처리

필터 체인은 애플리케이션을 구성하는 방법에 따라 더 길어지거나 짧아질 수 있다. 스프링 시큐리티에 있는 필터는 미리 정의된 Order를 가진다. 새 필터는 필처테인의 다른 필터를 기준으로 추가되며 기존 필터의 앞이나 뒤에 새로운 필터를 추가할 수 있다. 

## **책 버전(5.x) → LATEST 버전(6.x)의 차이점**

```scss
[HTTP Request]
       │
       ▼
[DelegatingFilterProxy (Servlet Filter)]
       │
       ▼
[FilterChainProxy]
       │
       ▼
[SecurityFilterChain (요청 URL 별 매칭)]
       │
       ├─▶ securityMatcher() 매칭됨
       │
       ▼
[Security Filters (순서대로)]
       │
       ├─▶ SecurityContextHolderFilter (SecurityContext 전략 설정)
       │
       ├─▶ WebAsyncManagerIntegrationFilter (Spring Web Async 연동)
       │
       ├─▶ CsrfFilter (CSRF 보호)
       │
       ├─▶ LogoutFilter (로그아웃 처리)
       │
       ├─▶ UsernamePasswordAuthenticationFilter (Form 기반 인증)
       │
       ├─▶ ConcurrentSessionFilter (세션 동시성 제어)
       │
       ├─▶ BearerTokenAuthenticationFilter (JWT, OAuth2 Bearer Token 인증)
       │
       ├─▶ OAuth2LoginAuthenticationFilter (OAuth2 Login 인증)
       │
       ├─▶ SAML2WebSsoAuthenticationFilter (SAML2 인증)
       │
       ├─▶ ExceptionTranslationFilter (인증/인가 예외 처리)
       │
       └─▶ FilterSecurityInterceptor (권한 검사)
       │
       ▼
[Controller (DispatcherServlet)]
       │
       ▼
[Response 처리 (ExceptionTranslationFilter 에서 예외 시 처리)]
```

### 필터의 동작 방식

- ServletContainer는 하나의 `DelegatingFilterProxy` 하나만 등록
- `DelegatingFilterProxy`는 이름이 `springSecurityFilterChain` 인 빈을 호출하고 이 빈은 `FilterChainProxy` 빈을 의미
- 5.x 버전에서는 `FilterChainProxy` 내부의 `SecurityFilterChain` 이라고 부르는 "체인"을 가지는데, 내부적으로 대부분 1개만 존재
- 6.x 버전으로 오면서 `SecurityFilterChain`을 여러 개 등록할 수 있게 되었음
- `FilterChainProxy`는 요청이 들어올 때마다 가장 먼저 매칭되는 체인을 선택
    
    ```scss
    FilterChainProxy
      ├─ SecurityFilterChain 1 (조건: /api/**)
      └─ SecurityFilterChain 2 (조건: /web/**)
    ```
    

### 필터 설정 방식

- 5.x의 경우 `WebSeucirtyConfigurerAdapter` 를 상속받아서 SecurityFilter 설정을 구체적으로 설정
- 6.x로 넘어오면서 해당 클래스가 deprecated 되었고 Security Context에 필터 체인을 등록하는 형식으로 변경됨
- `@EnableWebSecurity` 어노테이션이 Spring Security를 활성화하는 스위치
- `@EnableWebSecurity(debug = true)`로 설정하면 디버깅 모드를 활성화 할 수 있으며 각 요청마다 어떤 필터체인 구성이 활성화 되는지 확인할 수 있음
- `secyrityMatcher`를 이용하여 `SecurityFilterChain` 자체에 대한 matcher를 지정할 수 있음

## 9.2 체인에서 기존 필터 앞에 필터 추가

- 예제 시나리오
    - 모든 요청에 `Request-Id` 헤더가 있음
    - 헤더로 요청을 추적하므로 **헤더가 필수 데이터**이며 **인증을 수행하기 전에 헤더가 있는지 검증**
    - 헤더가 존재하지 않으면 요청 형식이 올바르지 않으므로 인증 프로세스를 타지 않도록 구현
- 구현 순서
    1. 필터를 구현한다
        1. 요청에 필요한 헤더가 있는지 확인하는 `RequestValidationFilter` 클래스 생성
    2. 필터 체인에 필터를 추가한다
        1. 구성 클래스에서 `configure()` 메서드를 재정의해 필터 체인에 필터를 추가한다

### 필터 구현

```java
public class RequestValidationFilter implements Filter {
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		var httpRequest = (HttpServletRequest) request;
		var httpResponse = (HttpServletResponse) response;
		
		String requestId = httpRequest.getHeader("Request-Id");
		
		if (requestId == null || requestId.isBlank()) {
			httpResponse.setStatus(HttpServletResponse.SC_BAD_REQEUST);
			return;
		}
		filterChain.doFilter(request, response);
	}
}
```

- doFilter() - 필터의 논리를 작성한다.
- 해당 시나리오의 논리는 `Request-Id` 헤더가 있는지 확인하고 헤더가 있으면 `doFilter()` 메서드를 호출하여 다음 필터로 요청을 전달하는 것이다. 헤더가 없다면 응답으로 `400 Bad Request` 를 반환한다.

### 필터 체인에 필터를 추가

```java
@Configuration
@EnableWebSecurity 
public class ProjectConfig {
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
          .httpBasic(Customizer.withDefaults()) // BasicAuthenticationFilter를 포함하기 위한 설정
	        .addFilterBefore(new RequestValidationFilter(),
	        BasicAuthenticationFilter.class)
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}
```

- addFilterBefore - `BasicAuthenticationFilter` 가 인증 프로세스를 담당하는 필터이므로 해당 필터 앞에 `RequestValidationFilter` 를 추가하여 인증 전에 Request-Id 헤더를 검증할 수 있음

## 9.3 체인에서 기존 필터 뒤에 필터 추가

- 예제 시나리오
    - 기존 인증 필터 이후에 로깅을 위한 필터 추가

### 필터 구현

```java
public class AuthenticationLogginFilter implements Filter {

	private final Logger logger = 
		Logger.getLogger(AuthenticationLoggingFilter.class.getName());
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		var httpRequest = (HttpServletRequest) request;
		
		String requestId = httpRequest.getHeader("Request-Id");
		
		logger.info("Successfully authenticated request with id " + requestId);
		
		filterChain.doFilter(request, response);
	}
}
```

### 필터 체인 설정

```java
@Configuration
@EnableWebSecurity 
public class ProjectConfig {
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
          .httpBasic(Customizer.withDefaults())
	        .addFilterBefore(new RequestValidationFilter(),
		        BasicAuthenticationFilter.class)
	        .addFilterAfter(new AuthenticationLoggingFilter(),
		        BasicAuthenticationFilter.class)
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}

```

## 9.4 필터 체인의 다른 필터 위치에 필터 추가

다른 필터 위치에 맞춤형 필터를 추가하는 과정

### 예제 시나리오

- 모든 요청에 대해 `Authorization` 헤더에 정적 키를 요구한다

### 필터 구현

```java
public class StaticKeyAuthenticationFilter implements Filter {

	@Value("${authorization.key}")
	private String authorizationKey;
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		var httpRequest = (HttpServletRequest) request;
		
		String authentication = httpRequest.getHeader("Authorization");
		
		if (authorizationKey.equals(authentication)) {
			filterChain.doFilter(request, response);
		} else {
			httpResponse.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
		}
	}
}
```

### 필터 체인에 필터 추가

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor 
public class ProjectConfig {

		private final StaticKeyAuthenticationFilter filter;
		
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
          .httpBasic(Customizer.withDefaults())
	        .addFilterAt(filter,
		        BasicAuthenticationFilter.class)
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}

```

- 필터를 BasicAuthenticationFilter 순서에 추가한다
- `addFilterAt`의 경우 목록에 추가하는 방식이므로 여러 개의 필터를 추가하면 순서가 보장되지 않는다
- `addFilterBefore` , `addFilterAfter`와 차이점은 기존 필터를 완전히 대체한다는 점

## 9.5 스프링 시큐티리가 제공하는 필터 구현

### OncePerRequestFilter

doFilter가 요청 당 한번만 실행되도록 하는 필터로 중복 실행을 방지한다. 

ExceptionTranslationFilter 예외가 발생하거나 servlet 내의 요청 등에 의해 필터가 중복실행될 가능성이 있다.

```java
public class StaticKeyAuthenticationFilter extends OncePerRequestFilter {

	private final Logger logger = 
		Logger.getLogger(AuthenticationLoggingFilter.class.getName());
	
	@Override
	public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) {
		var httpRequest = (HttpServletRequest) request;
		
		String requestId = httpRequest.getHeader("Request-Id");
		
		logger.info("Successfully authenticated request with id " + requestId);
		
		filterChain.doFilter(request, response);
	}
}
```

OncePerRequestFilter는 HTTP 필터만 지원한다. `shouldNotFilter`를 이용해 특정 요청에는 필터를 적용하지 않을 수 있다. 

# 10장 - CSRF 보호와 CORS 적용

## 10.1 애플리케이션에 CSRF(사이트 간 요청 위조) 보호 적용

`HTTP POST`를 구현할 때는 `CSRF 보호`를 비활성화하는 보조 명령을 추가해야 한다. 

## 10.1.1 스프링 시큐리티의 CSRF 보호가 작동하는 방식

### CSRF 공격

사용자가 웹 애플리케이션에 로그인 했다고 가정하며 사용자는 공격자에게 속아서 작업 중인 애플리케이션에서 특정 작업을 실행하는 스크립트가 포함된 페이지를 연다. 사용자가 로그인을 했기 때문에 위조 코드는 사용자의 인증 정보를 갖고 사용자 대신 작업을 수행할 수 있다. 

### CSRF 보호

CSRF 공격에서 사용자를 보호하기 위해서 웹 애플리케이션에서 프런트엔드만 변경 작업(GET, HEAD, TRACE, OPTIONS 외의 HTTP METHOD)을 수행할 수 있도록 보장한다. 그러면 외부 페이지가 사용자 대신 작업을 수행하는 것을 막을 수 있다. 

서버에 HTTP GET 요청이 들어오면 애플리케이션은 고유한 토큰을 생성하고, 헤더에 해당 토큰이 포함된 요청에 대해서만 변경 작업을 수행한다. 

CSRF 보호의 시작점은 필터 체인의 CsrfFilter라는 한 필터이다. CsrfFilter는 요청을 가로채고 변경 작업인 경우에는 토큰이 포함된 헤더가 있는지 확인한다. 토큰이 없거나 잘못된 토큰 값을 포함한 경우 요청을 거부하고 `403 Forbidden` 응답값을 반환한다. 

기본적으로 CsrfTokenRepository를 이용해 새 토큰 생성, 토큰 저장, 토큰 검증에 필요한 CSRF 토큰 값을 관리한다. CsrfTokenRepository는 랜덤 UUID로 토큰을 생성한다. repository는 직접 구현이 가능하다. 

CsrfFilter는 생성된 CSRF 토큰을 HTTP 요청의 `_csrf` attribute에 추가한다. CSRF 보호는 기본적으로 세션 기반이며 JWT와 같이 stateless 인증을 이용한다면 커스텀 설정을 통해 쿠키로 관리할 수 있다. 

### 예제 시나리오

- CSRF 보호를 비활성화 하지않고 POST 엔드포인트를 호출할 수 있도록 설정한다
- HTTP GET으로 엔드포인트를 호출할 때 앱이 생성하는 CSRF 토큰을 애플리케이션 콘솔에 출력한다
- 콘솔에서 토큰의 값을 복사하고 HTTP POST 호출에서 이용할 수 있도록 한다

### 맞춤형 CSRF 필터 클래스

```java
public class CsrfTokenLogger implements Filter {
	private Logger logger = Logger.getLogger(CsrfTokenLogger.class.getName());
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) {
		Object o = request.getAttribute("_csrf");
		CsrfToken token = (CsrfToken) o;
		
		logger.info("CSRF token " + token.getToken());
		filterChain.doFilter(request, response);
	}
}
```

### 필터를 필터 체인에 추가

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor 
public class ProjectConfig {

		private final StaticKeyAuthenticationFilter filter;
		
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
	        .addFilterAfter(new CsrfTokenLogger(), CsrfFilter.class)
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}

```

CsrfTokenRepository 인터페이스의 기본 구현은 HTTP 세션을 이용해 서버쪽에 토큰 값을 저장하므로 session ID도 기억해야 한다. 

### 10.1.2 실제 시나리오에서 CSRF 보호 사용

### 예제 시나리오

- 5장에서 만들었던 form Login 구현 애플리케이션에서 CSRF 토큰을 이용하는 방법을 확인한다

### 설정 클래스

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor 
public class ProjectConfig {

		@Bean
		public UserDetailsService uds() {
			var uds = new InMemoryUserDetailsManager();
			
			var u1 = User.withUsername("mary")
									 .password("12345")
									 .authorities("READ")
									 .build();
		  ubs.createUser(u1);
		  return uds;
		}
		
		@Bean
		public PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}
				
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
	        .addFilterAfter(new CsrfTokenLogger(), CsrfFilter.class)
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().authenticated()
            )
          .formLogin(form -> form
                .defaultSuccessUrl("/main", true));

        return http.build();
    }
}

```

- 설정 후 사용자가 로그인을 하면 csrf 토큰이 발행된다
- 로그인 후 변경 작업을 요청하려면 _csrf 토큰을 포함하여 요청을 전송해야 한다
- CSRF 토큰은 같은 서버가 프런트엔드와 백엔드 모두를 담당하는 단순한 아키텍처에서 잘 작동하지만 독립전인 경우 잘 동작하지 않는다.

## 10.1.3 CSRF 보호 맞춤 구성

### 예제 시나리오

- CSRF가 적용되는 경로 설정
- CSRF 토큰 관리

### 설정 클래스

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor 
public class ProjectConfig {
				
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
	        .csrf(c -> c.ignoringRequestMatchers("/ciao"))
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}

```

- 예제의 `ignoreAntMatchers` 는 deprecated
- `ignoringRequestMatchers`를 통해 CSRF 보호 메커니즘에서 제외할 경로를 나타낼 수 있다
- `AntMatchers`를 이용하려면 직접 matcher를 명시해주는 방법이 있다
    
    ```java
    http.csrf(c -> c.ignoringRequestMatchers(
            new AntPathRequestMatcher("/ciao")
        ));
    ```
    
- 정규식 패턴은 `RegesRequestMatcher`를 지정해서 사용할 수 있다
    
    ```java
    
    http
        .csrf(csrf -> csrf
            .ignoringRequestMatchers(new RegexRequestMatcher(".*[0-9].*", null))
        )
    ```
    
    - 두 번째 파라미터는 HTTP METHOD 지정, null로 지정하면 모든 메서드에 적용

### CSRF 토큰 관리 맞춤 구성

- CsrfToken - CSRF 토큰 자체를 기술
- CsrfTokenRepository - CSRF 토큰을 생성, 저장, 로드하는 객체를 기술

### CsrfToken

```java
public interface CsrfToken extends Serializable {
  String getHeaderName();

  String getParameterName();

  String getToken();
}
```

- CSRF 토큰을 포함하는 헤더의 이름 (기본 이름은 X-CSRF-TOKEN)
- 토큰의 값을 지정하는 요청의 특성 이름 (기본 이름은 _csrf)
- 토큰의 값

스프링 시큐리티는 DefualtCsrfToken이라는 구현을 기본적으로 제공한다.

### CsrfTokenRepository

```java
public interface CsrfTokenRepository {
  CsrfToken generateToken(HttpServletRequest request);

  void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response);

  CsrfToken loadToken(HttpServletRequest request);

  default DeferredCsrfToken loadDeferredToken(HttpServletRequest request, HttpServletResponse response) {
    return new RepositoryDeferredCsrfToken(this, request, response);
  }
}
```

애플리케이션이 토큰을 관리하는 방법을 변경하려면 해당 인터페이스를 구현해 맞춤형 구현을 프레임워크에 연결해야 한다.

### 예제 시나리오

- CSRF 토큰을 데이터베이스에 저장한다
- 토큰을 식별하기 위한 ID가 있다고 가정한다
- 고유 ID는 로그인 중에 얻으며 사용자가 로그인할 때마다 달라야 한다
- ID는 세션 ID를 대체한다
- 대안으로 수명이 정의된 CSRF 토큰을 이용하는 방법이 있다
- 토큰은 시간이 지나면 만료되며 특정 사용자 ID와 연결하지 않고 데이터베이스에 저장할 수 있다

### 테이블 정의

```sql
CREATE TABLE IF NOT EXISTS `spring`.`token` (
	`id` INT NOT NULL AUTO_INCREMENT,
	`identifier` VARCHAR(45) NULL,
	`token` TEXT NULL,
PRIMARY KEY (`id`));
```

### JPA Entity Class

```java
@Entity
public class Token {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private int id;
	
	private String identifier; // 클라이언트의 식별자
	private String token;	// 클라이언트를 위해 생성한 CSRF TOKEN
}
```

### JpaTokenRepository

```java
public interface JpaTokenRepository extends JpaRepository<Token, Integer> {
	Optional<Token> findTokenByIdentifier(String identifier);
}
```

### CsrfTokenRepository

```java
@RequiredArgsConstructor
public class CustomCsrfTokenRepository implements CsrfTokenRepository {
	
	private final JpaTokenRepository jpaTokenRepository;
	
	@Override
	public CsrfToken generateToken(HttpServletRequest httpServletRequest) {
		String uuid = UUID.randomUUID().toString();
		return new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", uuid);
	}
	
	@Override
	public void saveToken(CsrfToken token, HttpServletRequest request, HttpServletResponse response) {
		String identifier = httpServletRequest.getHeader("X-IDENTIFIER");
		Optional<Token> existingToken = jpaTokenRepository.findTokenByIdentifier(identifier);
		
		if (existingToken.isPresent()) {
			Token token = existingToken.get();
			token.setToken(csrfToken.getToken());
		} else {
			Token token = new Token();
			token.setToken(csrfToken.getToken());
			token.setIdentifier(identifier);
			jpaTokenRepository.save(token);
		}
	}

	@Override
  public CsrfToken loadToken(HttpServletRequest request) {
	  String identifier = httpServletRequest.getHeader("X-IDENTIFIER");
		Optional<Token> existingToken = jpaTokenRepository.findTokenByIdentifier(identifier);
		
		if (existingToken.isPresent()) {
			Token token = existingToken.get();
			return new DefaultCsrfToken(
				"X-CSRF-TOKEN",
				"_csrf",
				token.getToken());
		}
		return null;
  }

}
```

스프링 컨텍스트에서 JpaTokenRepository 인스턴스를 주입해 데이터베이스에 대한 접근 권한을 얻는다.

CSRF 토큰을 데이터베이스에서 얻거나 데이터베이스에 저장한다. generateToken()을 이용해 새 토큰을 생성할 수 있다. 

### CsrfConfigurer

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor 
public class ProjectConfig {

		@Bean
		public CsrfTokenRepository customTokenRepository() {
			return new CustomCsrfTokenRepository();
		}
				
	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
	        .csrf(c -> c.ignoringRequestMatchers("/ciao")
							        .csrfTokenRepository(customTokenRepositor())
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}
```

- 맞춤형 CsrfTokenRepository 연결

## 10.2 CORS 이용

## 10.2.1 CORS 작동 방식

애플리케이션이 두 개의 서로 다른 도메인 간에 호출하는 것은 모두 금지된다. CORS를 이용하면 애플리케이션이 요청을 허용할 도메인, 공유할 수 있는 세부 정보를 지정할 수 있다. CORS 메커니즘은 HTTP 헤더를 기반으로 작동한다.

- Access-Control-Allow-Origin : 도메인의 리소스에 접근할 수 있는 외부 도메인(origin)을 지정한다
- Access-Control-Allow-Methods : 다른 도메인에 대한 접근을 허용하지만 특정 HTTP Method 방식만 허용하고 싶을 때 지정할 수 있다
- Access-Control-Allow-Headers : 특정 요청에 이용할 수 있는 헤더에 제한을 추가한다

### 예제 시나리오

- CORS 적용

### 설정 클래스

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor 
public class ProjectConfig {

	  @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
	        .csrf(AbstractHttpConfigurer::disable)
	        .authorizeHttpRequests(authorize -> authorize
                .anyRequest().permitAll()
            );

        return http.build();
    }
}
```

- CORS에 관해 아무것도 구성하지 않으면 요청이 들어왔을 때 Access-Control-Allow-Origin HTTP 헤더가 없어서 응답이 수락되지 않았다는 오류가 발생한다
- 기본적으로 스프링 부트는 CORS 관련 설정을 지정하지 않는다

### CORS 정책

CORS에 대한 설정은 제한을 가하는 것이 아닌 교차 도메인 호출의 엄격한 제약을 완화하도록 도와주는 것에 가깝다

종종 브라우저는 preflight 요청을 보내는데 HTTP OPTIONS 방식으로 호추한다. 이 요청이 실패하면 원래 요청을 수락하지 않는다.

## 10.2.2 @CrossOrigin 어노테이션으로 CORS 정책 적용

```java
@PostMapping("/test")
@CrossOrigin("http://localhost:8080")
public string test() {
	//...
}
```

- `@CrossOrigin({"a.com", "b.com"}) 형태도 가능

### CORS Config로 설정
```java
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors
                .configurationSource(corsConfigurationSource())
            )
            .authorizeHttpRequests(authz -> authz
                .anyRequest().permitAll()
            );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(List.of("example.com", "example.org")); 
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE")); 
        configuration.setAllowedHeaders(List.of("*")); 
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 적용할 URL 패턴

        return source;
    }
}
```