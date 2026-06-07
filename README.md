## AuditableRandom

`AuditableRandom` — ChaCha20 기반 **감사 가능(재현 가능) 난수 생성기**와 그 벤치마크.

각 난수 추출은 고유한 `tick`을 함께 산출하며, `(seed, userId, tick)` 세 값만 있으면
키스트림 블록을 **바이트 단위로 동일하게 재현**할 수 있다. 추첨·배정처럼 사후에 "정말 공정했는지"를
검증해야 하는 곳에서, 결과를 감사 로그로 남겼다가 그대로 다시 계산해 대조할 수 있다.

### 특징
- **재현성**: 비밀 seed + `userId` + 발급 `tick` → 동일 keystream. 감사 로그로 추첨 결과를 사후 검증.
- **암호학적 품질**: RFC 8439 ChaCha20(20 라운드) keystream. 분포 균등성은 카이제곱 검정으로 검증.
- **편향 없는 범위 추출**: 거부 표본추출(rejection sampling)로 modulo bias 제거 — 모든 결과값이 동일 확률.
- **SIMD 최적화**: 블록 함수는 `Vector128<uint>` 기반이며, 회전 16/8비트는 바이트 셔플 1연산으로 처리.
- **스레드 안전**: `tick` 발급은 `Interlocked` CAS로 원자적. 정적 메서드는 동시 호출에 안전하다.

### 빠른 시작

```csharp
using System.Security.Cryptography;
using RandomLib;

// 1) 프로세스 시작 시 단 한 번, 32바이트 seed를 등록한다.
byte[] seed = RandomNumberGenerator.GetBytes(32);
AuditableRandom.Initialize(seed);

// 2) 난수 추출 — tick을 함께 받아 (userId, tick)을 감사 로그에 저장한다.
Int32 dice = AuditableRandom.Next("user-123", 1, 7, out Int64 tick); // [1, 7)
// → dice와 (userId="user-123", tick)을 저장.

// 3) 사후 재현(감사) — 동일 (userId, tick)으로 keystream 블록을 다시 만들어 검증한다.
byte[] block = AuditableRandom.GetBlockChaCha20("user-123", tick);
// 저장 당시와 동일한 추출 로직을 block에 적용하면 dice가 그대로 나온다.

// 과거 seed로 재현해야 하면 명시 seed 오버로드를 쓴다(Initialize와 무관하게 동작).
byte[] past = AuditableRandom.GetBlockChaCha20(oldSeed, "user-123", tick);
```

> `Initialize`는 프로세스 수명 동안 **한 번만** 성공한다(이중 호출 시 예외). seed는 정확히 32바이트여야 한다.

### API 요약

| 메서드 | 설명 |
|---|---|
| `Initialize(seed[, resumeAfterTick])` | 32바이트 seed 등록(프로세스당 1회) |
| `Next(...)` / `NextInt64(...)` | 부호 있는 정수 `[0, max)` 또는 `[min, max)` |
| `NextUInt32(...)` / `NextUInt64(...)` | 부호 없는 정수 `[0, max)` 또는 `[min, max)` |
| `NextDouble(...)` / `NextSingle(...)` | `[0, 1)` 부동소수 |
| `Shuffle(IList<T> \| Span<T> \| T[])` | Fisher-Yates 셔플(감사 대상 아님) |
| `GetBlockChaCha20(...)` | 64바이트 keystream 블록 생성/재현 |

정수·부동소수 메서드는 모두 다음 오버로드 축을 공유한다.
- `userId` 생략(빈 사용자) / `userId` 지정 — `userId`는 결과를 사용자에 바인딩(xxHash3로 nonce에 묶음).
- `out Int64 tick` 생략 / 지정 — 감사 로그 저장용 tick을 받는다.

```csharp
AuditableRandom.NextDouble();                          // 빈 userId, tick 버림
AuditableRandom.NextDouble(out Int64 tick);            // 빈 userId, tick 받음
AuditableRandom.Next(1, 7);                            // [1,7), 빈 userId
AuditableRandom.Next("user-1", 1, 7, out Int64 tick);  // [1,7), userId + tick
AuditableRandom.NextUInt64("user-1", 1000UL);          // [0,1000)
```

### 재시작 간 nonce 유일성 보장

`(seed, nonce)` 묶음을 재사용하지 않아야 한다. nonce에는 `tick`이 들어간다. system clock은
뒤로 갈 수 있어, **같은 seed를 재사용하면서 재시작** 하는 사이에 tick이 겹칠 위험이 있다. 직전 실행에서
발급한 최대 `tick`을 내구성 있게 저장했다가 다음 시작 시 넘기면, 이후 모든 tick이 그 값을 초과하도록 보장된다.

```csharp
// 직전 실행에서 저장한 마지막 tick을 넘겨 재시작 간 nonce 겹침을 막는다.
AuditableRandom.Initialize(seed, resumeAfterTick: lastIssuedTick);
```

> 효과를 보려면 **호출자(앱)** 가 발급 tick의 최댓값을 영속화했다가 재시작 시 넘겨줘야 한다.
> 라이브러리는 메커니즘만 제공한다. `0`이면 시간 기준만 사용한다.

### 주의

- **리틀엔디안 의존**: 성능을 위해 키/논스 적재와 출력 기록을 LE로 처리한다(.NET 실행 환경은 사실상 전부 LE).
  빅엔디안으로 이식하면 출력이 달라져 재현이 깨진다.
- **Shuffle은 감사 대상이 아니다**(틱을 저장하지 않음). 결과 재현이 필요 없는 셔플 전용이다.

## 벤치마크

```
dotnet run --project Benchmarks -c Release
```
