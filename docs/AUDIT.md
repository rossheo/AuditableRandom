# AuditableRandom 감사 재현 명세

이 문서는 `AuditableRandom`이 산출한 난수 값을 **외부 감사자가 독립적으로 재현**하기 위한 완전한 명세다.
.NET이나 이 라이브러리 없이도, 아래 절차를 다른 언어로 구현하면 동일한 값을 얻을 수 있다.

## 1. 감사 로그에 기록해야 하는 것

| 항목 | 설명 |
|---|---|
| `seed` | 32바이트 ChaCha20 키. **비밀값**이므로 감사 로그가 아닌 안전한 별도 저장소에 보관한다. |
| `userId` | 추출에 사용한 사용자 식별자 문자열 원본. 빈 문자열(`""`)일 수 있다. |
| `tick` | 추출 시 `out Int64 tick`으로 받은 값. 추출마다 프로세스 전역에서 고유하다. |
| 추출 종류와 인자 | 어떤 메서드를 어떤 범위로 호출했는지 (예: `NextInt32(userId, 1000)`). 값 유도에 필요하다. |
| (Fill만) 길이 | `Fill`로 생성한 keystream의 바이트 길이. |

> tick은 프로세스 시작 시각(UTC)의 `DateTime.Ticks`(100ns 단위)를 기준으로 한 단조 증가 값이므로,
> 추출이 일어난 시각을 근사 역산하는 용도로도 쓸 수 있다.

## 2. keystream 블록 재현

하나의 추출은 64바이트 ChaCha20 keystream 블록 하나에서 유도된다. 블록은 다음과 같이 만든다.

### 2.1 userId 해시

```
hash64 = XxHash3-64( userId의 UTF-16 리틀엔디안 바이트 )
```

- 인코딩 변환 없이 .NET 문자열의 메모리 표현(UTF-16 LE) 그대로를 해싱한다.
  예: `"AB"` → 바이트 `41 00 42 00`.
- 빈 문자열은 빈 입력의 xxHash3-64 값(`0x2D06800538D394C2`)이 된다.

### 2.2 nonce와 counter 구성

RFC 8439 ChaCha20의 12바이트 nonce와 32비트 초기 counter를 다음과 같이 채운다.

```
nonce[0..8)  = tick   (Int64, big-endian)
nonce[8..12) = hash64의 상위 32비트 (big-endian)
counter      = hash64의 하위 32비트
```

### 2.3 블록 생성

```
block = ChaCha20_Block(key = seed, nonce, counter)   // RFC 8439 §2.3, 64바이트
```

라이브러리의 구현은 RFC 8439 §2.3.2 테스트 벡터로 검증되어 있다(`ChaCha20BlockTests`).
라이브러리로 직접 재현하려면 `AuditableRandom.GetBlockChaCha20(seed, userId, tick)`을 호출한다.

### 2.4 임의 길이(Fill)의 멀티블록

`Fill`로 생성한 keystream은 블록마다 counter를 1씩 증가시킨다(RFC 8439 표준 방식).

```
output[ 0.. 64) = ChaCha20_Block(seed, nonce, counter)
output[64..128) = ChaCha20_Block(seed, nonce, counter + 1)
...
```

마지막 블록은 필요한 길이만큼만 잘라 쓴다. 따라서 생성 당시보다 짧은 길이로 재현하면 동일한 접두(prefix)를 얻는다.
라이브러리로는 `AuditableRandom.Fill(seed, userId, tick, destination)`을 호출한다.

## 3. 값 유도 (Lemire)

블록에서 최종 값을 만드는 규칙. **저장된 tick의 블록에는 항상 수락되는 워드가 존재한다**
(생성 시 한 블록의 모든 워드가 거부되면 새 tick으로 재시도하고, 최종 성공한 tick만 반환하기 때문).

### 3.1 Lemire multiply-shift 거부표본추출

`raw`(N비트 부호 없는 정수)를 `[0, range)`로 편향 없이 사상한다. N은 32 또는 64.

```
product   = raw * range            // 2N비트 곱
low       = product의 하위 N비트
value     = product의 상위 N비트   // = product >> N
threshold = 2^N mod range

raw 수락 ⇔ low ≥ threshold        // 거부되면 블록의 다음 워드로 진행
```

### 3.2 메서드별 규칙

| 메서드 | 워드 읽기 | 유도 |
|---|---|---|
| `NextUInt32(userId, max)` / `NextInt32(userId, max)` | 블록을 앞에서부터 4바이트 **big-endian** 워드 16개로 스캔 | 첫 번째 수락 워드에 Lemire(N=32, range=max) 적용 |
| `NextUInt64(userId, max)` / `NextInt64(userId, max)` | 블록을 앞에서부터 8바이트 **big-endian** 워드 8개로 스캔 | 첫 번째 수락 워드에 Lemire(N=64, range=max) 적용 |
| `NextUInt32(userId)` / `NextInt32(userId)` (전 범위) | 앞 4바이트 **big-endian** → `raw`(UInt32) | 거부·축소 없음. `UInt32`는 `raw` 그대로, `Int32`는 `unchecked((int)raw)`(2의 보수 재해석) |
| `NextUInt64(userId)` / `NextInt64(userId)` (전 범위) | 앞 8바이트 **big-endian** → `raw`(UInt64) | 거부·축소 없음. `UInt64`는 `raw` 그대로, `Int64`는 `unchecked((long)raw)`(2의 보수 재해석) |
| `NextDouble(userId)` | 앞 8바이트 big-endian → `raw` | `(raw >> 11) × 2⁻⁵³` |
| `NextSingle(userId)` | 앞 4바이트 big-endian → `raw` | `(raw >> 9) × 2⁻²³` |
| `Hits(userId, numerator, denominator)` | `NextInt32(userId, denominator)`와 동일 | 뽑힌 값이 `numerator` 미만이면 명중(`true`). 명중 확률은 정확히 `numerator/denominator` |
| `Hits(userId, probability)` (부동소수) | `NextDouble(userId)`와 동일(앞 8바이트) | 뽑힌 값이 `probability` 미만이면 명중(`true`). 거부 없이 직접 재현 |
| `[min, max)` 범위 오버로드 | 위와 동일 | `range = max − min`으로 뽑은 값에 `min`을 더한다 |
| `Shuffle` | — | **감사/재현 대상이 아니다** (tick을 반환하지 않음) |

### 3.3 참조 구현 (C#)

```csharp
// NextInt32(userId, max)로 뽑힌 값을 (seed, userId, tick)에서 재현한다.
static int Reproduce(byte[] seed, string userId, long tick, uint max)
{
    byte[] block = AuditableRandom.GetBlockChaCha20(seed, userId, tick);
    for (int i = 0; i <= 64 - 4; i += 4)
    {
        uint raw = BinaryPrimitives.ReadUInt32BigEndian(block.AsSpan(i, 4));
        ulong product = (ulong)raw * max;
        uint low = (uint)product;
        if (low >= max || low >= unchecked(0u - max) % max) // low >= (2^32 mod max)
            return (int)(product >> 32);
    }
    throw new InvalidDataException("저장된 tick의 블록에는 항상 수락 워드가 있어야 한다.");
}
```
