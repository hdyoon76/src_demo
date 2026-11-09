# Secure Notes Service (Java)

소스코드 보안 솔루션의 정적 분석 데모를 위한 작은 Java 웹 서비스입니다. 회원가입, 로그인, 개인 메모 저장/조회 흐름 안에 보안 코딩 사례를 담았습니다. 데이터는 메모리에 저장되며 서버를 재시작하면 초기화됩니다.

## 실행

JDK 17 이상이 필요합니다. Maven, Gradle, 외부 라이브러리는 필요하지 않습니다. `java -version`과 `javac -version`으로 확인할 수 있습니다.

```sh
javac --add-modules jdk.httpserver -d out src/main/java/demo/SecureNotesServer.java
java --add-modules jdk.httpserver -cp out demo.SecureNotesServer
```

Windows에서는 `run.bat`을 실행해도 됩니다. macOS/Linux에서는 `sh run.sh`를 실행합니다.

기본 주소는 `http://127.0.0.1:8080`입니다. `PORT` 환경 변수로 포트를 바꿀 수 있습니다.

## 간단한 사용 예

```sh
curl -i -X POST http://127.0.0.1:8080/register -d 'username=alice&password=CorrectHorse12'
curl -i -c cookies.txt -X POST http://127.0.0.1:8080/login -d 'username=alice&password=CorrectHorse12'
curl -i -b cookies.txt -X POST http://127.0.0.1:8080/note -d 'text=hello%20secure%20world'
curl -i -b cookies.txt http://127.0.0.1:8080/note
```

## 데모에서 볼 보안 포인트

- 비밀번호 정책 검증 후 평문 대신 랜덤 salt와 PBKDF2-HMAC-SHA256으로 저장
- `SecureRandom` 기반의 예측하기 어려운 세션 토큰, `HttpOnly`/`SameSite` 쿠키
- 인증된 사용자 계정에 메모 조회/저장을 한정해 다른 사용자 데이터 접근 방지
- 요청 본문 크기와 입력 길이 제한, 사용자 이름 형식 검증
- 로그인 실패 메시지를 통일해 계정 존재 여부 노출 완화
- 응답 JSON 문자열 이스케이프, `nosniff` 및 `no-store` 응답 헤더

데모를 단순하게 유지하기 위해 인메모리 저장소를 사용하며, 운영 서비스에 필요한 TLS 종료, CSRF 방어, 세션 만료/폐기, 로그인 시도 제한, 영속 저장소, 감사 로깅은 포함하지 않습니다. 따라서 이 예제는 보안 설계 패턴을 보여주는 샘플이며 운영 배포용 서버가 아닙니다.
