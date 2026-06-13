using System.Buffers.Binary;
using System.Security.Cryptography;
using RandomLib;
using Xunit.Abstractions;

namespace RandomLib.Tests;

/// <summary>
/// 자체 구현한 ChaCha20 블록 함수가 RFC 8439 표준과 정합한지 보장한다.
/// (이 KAT가 깨지면 ChaCha20Block 구현이 표준에서 벗어난 것이다.)
/// </summary>
public class ChaCha20BlockTests
{
	[Fact]
	public void Rfc8439_Section232_BlockFunction_Kat()
	{
		// RFC 8439 §2.3.2: key=00..1f, nonce=00:00:00:09:00:00:00:4a:00:00:00:00, counter=1
		byte[] key = new byte[32];
		for (Int32 i = 0; i < 32; i++)
			key[i] = (byte)i;
		byte[] nonce = [0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00];

		byte[] block = new byte[64];
		AuditableRandom.ChaCha20Block(key, nonce, 1, block);

		Assert.Equal(
			"10F1E7E4D13B5915500FDD1FA32071C4" +
			"C7D1F4C733C068030422AA9AC3D46C4E" +
			"D2826446079FAA0914C2D705D98B02A2" +
			"B5129CD1DE164EB9CBD083E8A2503C4E",
			Convert.ToHexString(block));
	}
}

/// <summary>
/// 공개 API(GetBlockChaCha20)를 통과하는 결과를 박제해 재현성을 고정한다.
/// tick 인코딩 + xxHash3(userId) + ChaCha20 블록 전체 파이프라인을 한 번에 동결하므로,
/// 이후 어느 단계가 바뀌어도(감사 재현이 깨지는 변경) 이 테스트가 잡아낸다.
/// 기대값은 검증된 현재 구현으로 실측해 박은 골든 벡터다.
/// </summary>
public class ReproducibilityTests
{
	// 고정 시드(0xA0..0xBF) — 명시 시드 overload는 전역 Initialize와 무관하다.
	private static byte[] Seed()
	{
		byte[] s = new byte[32];
		for (Int32 i = 0; i < 32; i++)
			s[i] = (byte)(0xA0 + i);
		return s;
	}

	private const Int64 FixedTick = 0x0123456789ABCDEFL;

	[Fact]
	public void GoldenVector_WithUserId()
	{
		byte[] block = AuditableRandom.GetBlockChaCha20(Seed(), "user-0000000000000001", FixedTick);
		Assert.Equal(
			"51632928383C65D8E9C1569AF2FDD8F04E59130F4695342E7E29812CF4D560DD" +
			"B19A87B4906A1EEE40967FA3DD1665D8E115DD3B88D5803E9999CEA1F7EA64A2",
			Convert.ToHexString(block));
	}

	[Fact]
	public void GoldenVector_EmptyUserId()
	{
		byte[] block = AuditableRandom.GetBlockChaCha20(Seed(), string.Empty, FixedTick);
		Assert.Equal(
			"9920948603E3546C71DBA31620B9EF98537EEA384010A65C965346EFCC5084AA" +
			"D96A62B6C55EFE0AA323D42CA687F9605D39506D5C1524550DB920201194E2C7",
			Convert.ToHexString(block));
	}

	[Fact]
	public void SameInputs_ReproduceIdentically()
	{
		byte[] a = AuditableRandom.GetBlockChaCha20(Seed(), "abc", 12345);
		byte[] b = AuditableRandom.GetBlockChaCha20(Seed(), "abc", 12345);
		Assert.Equal(a, b);
	}

	[Fact]
	public void DifferentTick_ProducesDifferentBlock()
	{
		byte[] a = AuditableRandom.GetBlockChaCha20(Seed(), "abc", 1);
		byte[] b = AuditableRandom.GetBlockChaCha20(Seed(), "abc", 2);
		Assert.NotEqual(a, b);
	}

	[Fact]
	public void DifferentUserId_ProducesDifferentBlock()
	{
		byte[] a = AuditableRandom.GetBlockChaCha20(Seed(), "userA", 1);
		byte[] b = AuditableRandom.GetBlockChaCha20(Seed(), "userB", 1);
		Assert.NotEqual(a, b);
	}

	[Fact]
	public void DifferentSeed_ProducesDifferentBlock()
	{
		byte[] other = Seed();
		other[0] ^= 0xFF;
		byte[] a = AuditableRandom.GetBlockChaCha20(Seed(), "abc", 1);
		byte[] b = AuditableRandom.GetBlockChaCha20(other, "abc", 1);
		Assert.NotEqual(a, b);
	}

	[Fact]
	public void EmptyInput_XxHash3_MatchesAuditSpecConstant() =>
		// docs/AUDIT.md 2.1절에 박은 빈 userId 해시 상수와 실제 구현이 일치해야 한다.
		Assert.Equal(0x2D06800538D394C2UL,
			System.IO.Hashing.XxHash3.HashToUInt64(ReadOnlySpan<byte>.Empty));
}

/// <summary>
/// 카이제곱 검정으로 ChaCha20 블록 출력의 균등 분포를 검증한다.
/// GetBlockChaCha20(seed, userId, tick) 오버로드를 사용하므로 Initialize() 없이 독립 실행된다.
/// 각 검정의 임계값은 α=0.001 수준이므로, CSPRNG에서 이 임계값을 초과할 확률은 사실상 0이다.
/// </summary>
public class UniformDistributionTests(ITestOutputHelper output)
{
	private static byte[] Seed()
	{
		byte[] s = new byte[32];
		for (Int32 i = 0; i < 32; i++)
			s[i] = (byte)(0xC0 + i);
		return s;
	}

	// 카이제곱 임계값 (α=0.001): 통계표 기준 — ChaCha20은 사실상 통과 보장
	private const double ChiSq9Df = 27.877;    // 9 자유도 (10-버킷 검정)
	private const double ChiSq255Df = 310.457; // 255 자유도 (256-버킷 바이트 검정)

	// χ²/df ≈ 1.0이 이상적. 1.5 이하: 우수, 2.5 이하: 양호, 초과: 보통
	private static string UniformityGrade(double chiSq, Int32 df) =>
		(chiSq / df) switch { <= 1.5 => "우수", <= 2.5 => "양호", _ => "보통" };

	private void WriteQuality(double chiSq, Int32 df, Int32[] counts, double expected)
	{
		double maxDevPct = counts.Max(c => Math.Abs(c - expected)) / expected * 100.0;
		output.WriteLine(
			$"균등 품질: {UniformityGrade(chiSq, df)}  " +
			$"χ²/df={chiSq / df:F3} (기댓값 1.0)  " +
			$"최대 편차 {maxDevPct:F1}%");
	}

	[Fact]
	public void ByteOutput_ChiSquared_IsUniform()
	{
		// 1000 블록 × 64 바이트 = 64,000 샘플, 256 버킷, 버킷당 기대값 = 250
		const Int32 NumBlocks = 1000;
		const Int32 Buckets = 256;
		double expected = NumBlocks * 64.0 / Buckets;

		Int32[] counts = new Int32[Buckets];
		byte[] seed = Seed();
		for (Int32 i = 0; i < NumBlocks; i++)
		{
			byte[] block = AuditableRandom.GetBlockChaCha20(seed, "byte-dist", (Int64)i + 1);
			foreach (byte b in block)
				counts[b]++;
		}

		double chiSq = counts.Sum(c => Math.Pow(c - expected, 2) / expected);
		output.WriteLine($"샘플: {NumBlocks * 64:N0}  버킷: {Buckets}  기대값/버킷: {expected:F0}");
		output.WriteLine($"χ²={chiSq:F3}  임계값={ChiSq255Df} (255 df, α=0.001)  여유={ChiSq255Df - chiSq:F3}");
		WriteQuality(chiSq, Buckets - 1, counts, expected);
		Assert.True(chiSq < ChiSq255Df,
			$"바이트 균등성 실패: χ²={chiSq:F2} > 임계값 {ChiSq255Df} (255 df, α=0.001)");
	}

	[Fact]
	public void IntegerBuckets_ChiSquared_IsUniform()
	{
		// 10,000 샘플, 10 버킷, 버킷당 기대값 = 1,000
		const Int32 Buckets = 10;
		const Int32 Samples = 10_000;
		double expected = (double)Samples / Buckets;

		Int32[] counts = new Int32[Buckets];
		byte[] seed = Seed();
		for (Int64 tick = 1; tick <= Samples; tick++)
		{
			byte[] block = AuditableRandom.GetBlockChaCha20(seed, string.Empty, tick);
			UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block);
			counts[raw % (UInt32)Buckets]++;
		}

		double chiSq = counts.Sum(c => Math.Pow(c - expected, 2) / expected);
		output.WriteLine($"샘플: {Samples:N0}  버킷: {Buckets}  기대값/버킷: {expected:F0}");
		output.WriteLine($"버킷별 카운트: [{string.Join(", ", counts)}]");
		output.WriteLine($"χ²={chiSq:F3}  임계값={ChiSq9Df} (9 df, α=0.001)  여유={ChiSq9Df - chiSq:F3}");
		WriteQuality(chiSq, Buckets - 1, counts, expected);
		Assert.True(chiSq < ChiSq9Df,
			$"정수 버킷 균등성 실패: χ²={chiSq:F2} > 임계값 {ChiSq9Df} (9 df, α=0.001)");
	}

	[Fact]
	public void DoubleOutput_ChiSquared_IsUniform()
	{
		// NextDouble과 동일한 추출 로직(big-endian uint64 >> 11, ×2⁻⁵³)으로 분포 검정
		const Int32 Buckets = 10;
		const Int32 Samples = 10_000;
		double expected = (double)Samples / Buckets;

		Int32[] counts = new Int32[Buckets];
		byte[] seed = Seed();
		for (Int64 tick = 1; tick <= Samples; tick++)
		{
			byte[] block = AuditableRandom.GetBlockChaCha20(seed, "dbl-dist", tick);
			UInt64 raw = BinaryPrimitives.ReadUInt64BigEndian(block);
			double value = (raw >> 11) * (1.0 / (1UL << 53)); // [0, 1)
			counts[(Int32)(value * Buckets)]++;
		}

		double chiSq = counts.Sum(c => Math.Pow(c - expected, 2) / expected);
		output.WriteLine($"샘플: {Samples:N0}  버킷: {Buckets}  기대값/버킷: {expected:F0}");
		output.WriteLine($"버킷별 카운트: [{string.Join(", ", counts)}]");
		output.WriteLine($"χ²={chiSq:F3}  임계값={ChiSq9Df} (9 df, α=0.001)  여유={ChiSq9Df - chiSq:F3}");
		WriteQuality(chiSq, Buckets - 1, counts, expected);
		Assert.True(chiSq < ChiSq9Df,
			$"double 버킷 균등성 실패: χ²={chiSq:F2} > 임계값 {ChiSq9Df} (9 df, α=0.001)");
	}

	[Fact]
	public void LemireDerivation_ChiSquared_IsUniform()
	{
		// NextUInt32와 동일한 Lemire 유도(내부 TryReduce)를 keystream에 적용해
		// 유도식 자체가 편향을 만들지 않는지 검정한다(기존 검정들은 % 버킷을 직접 적용).
		const Int32 Buckets = 10;
		const Int32 Samples = 10_000;
		double expected = (double)Samples / Buckets;

		Int32[] counts = new Int32[Buckets];
		byte[] seed = Seed();
		Span<byte> block = stackalloc byte[64];
		for (Int64 tick = 1; tick <= Samples; tick++)
		{
			AuditableRandom.GetBlockChaCha20(seed, "lemire-dist", tick, block);
			for (Int32 i = 0; i <= 64 - 4; i += 4)
			{
				UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i, 4));
				if (AuditableRandom.TryReduce(raw, (UInt32)Buckets, out UInt32 value))
				{
					counts[value]++;
					break;
				}
			}
		}

		double chiSq = counts.Sum(c => Math.Pow(c - expected, 2) / expected);
		output.WriteLine($"샘플: {Samples:N0}  버킷: {Buckets}  기대값/버킷: {expected:F0}");
		output.WriteLine($"버킷별 카운트: [{string.Join(", ", counts)}]");
		output.WriteLine($"χ²={chiSq:F3}  임계값={ChiSq9Df} (9 df, α=0.001)  여유={ChiSq9Df - chiSq:F3}");
		WriteQuality(chiSq, Buckets - 1, counts, expected);
		Assert.True(chiSq < ChiSq9Df,
			$"Lemire 유도 균등성 실패: χ²={chiSq:F2} > 임계값 {ChiSq9Df} (9 df, α=0.001)");
	}

	[Fact]
	public void SameUser_LargeTickGaps_ChiSquared_IsUniform()
	{
		// 동일 유저가 1분~1시간 간격으로 요청할 때의 균등성 검증.
		// tick이 드문드문 퍼져 있어도 nonce 고유성이 유지되므로 분포가 균등해야 한다.
		const Int32 Buckets = 10;
		const Int32 Samples = 10_000;
		// DateTime.Ticks 단위: 1틱 = 100ns
		const Int64 MinGap = 60L * 10_000_000;       // 1분
		const Int64 MaxGap = 3_600L * 10_000_000;    // 1시간
		const string UserId = "user-large-gap-test";
		double expected = (double)Samples / Buckets;

		// 간격 생성용 별도 시드 — 콘텐츠 시드(0xC0..)와 독립
		byte[] gapSeed = new byte[32];
		for (Int32 i = 0; i < 32; i++) gapSeed[i] = (byte)(0xD0 + i);

		Int32[] counts = new Int32[Buckets];
		byte[] seed = Seed();
		// 현실적인 기준 시각: 2025-01-01 UTC
		Int64 tick = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc).Ticks;

		for (Int32 i = 0; i < Samples; i++)
		{
			byte[] block = AuditableRandom.GetBlockChaCha20(seed, UserId, tick);
			UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block);
			counts[raw % (UInt32)Buckets]++;

			// 다음 요청까지의 간격을 결정론적으로 생성 [MinGap, MaxGap)
			byte[] gapBlock = AuditableRandom.GetBlockChaCha20(gapSeed, string.Empty, (Int64)i + 1);
			UInt64 gapRaw = BinaryPrimitives.ReadUInt64BigEndian(gapBlock);
			tick += MinGap + (Int64)(gapRaw % (UInt64)(MaxGap - MinGap));
		}

		double chiSq = counts.Sum(c => Math.Pow(c - expected, 2) / expected);
		output.WriteLine($"샘플: {Samples:N0}  버킷: {Buckets}  기대값/버킷: {expected:F0}");
		output.WriteLine($"tick 간격: {MinGap / 10_000_000 / 60}분 ~ {MaxGap / 10_000_000 / 60}분");
		output.WriteLine($"버킷별 카운트: [{string.Join(", ", counts)}]");
		output.WriteLine($"χ²={chiSq:F3}  임계값={ChiSq9Df} (9 df, α=0.001)  여유={ChiSq9Df - chiSq:F3}");
		WriteQuality(chiSq, Buckets - 1, counts, expected);
		Assert.True(chiSq < ChiSq9Df,
			$"대형 간격 균등성 실패: χ²={chiSq:F2} > 임계값 {ChiSq9Df} (9 df, α=0.001)");
	}
}

/// <summary>
/// 당첨 확률 1%인 추첨을 10명의 사용자에 대해 반복 실행하며,
/// 각 사용자의 "연속 미당첨(streak)" 길이를 수집한다. 최장 기록 하나만이 아니라
/// 상위 3개(TOP 3) 연속 미당첨 streak을 사용자별로 모아 표시한다.
/// 명시 seed 경로(GetBlockChaCha20(seed, userId, tick))를 쓰므로
/// Initialize() 없이 독립적이고 재현 가능하게 실행된다.
/// </summary>
public class NoWinStreakTests(ITestOutputHelper output)
{
	private static byte[] Seed()
	{
		byte[] s = new byte[32];
		for (Int32 i = 0; i < 32; i++)
			s[i] = (byte)(0xE0 + i);
		return s;
	}

	[Fact]
	public void AuditableRandom_Top3NoWinStreaks_PerUser_100Draws() => RunTop3NoWinStreaks(100);

	[Fact]
	public void AuditableRandom_Top3NoWinStreaks_PerUser_200Draws() => RunTop3NoWinStreaks(200);

	[Fact]
	public void AuditableRandom_Top3NoWinStreaks_PerUser_300Draws() => RunTop3NoWinStreaks(300);

	[Fact]
	public void AuditableRandom_Top3NoWinStreaks_PerUser_400Draws() => RunTop3NoWinStreaks(400);

	[Fact]
	public void AuditableRandom_Top3NoWinStreaks_PerUser_500Draws() => RunTop3NoWinStreaks(500);

	[Fact]
	public void AuditableRandom_Top3NoWinStreaks_PerUser_100000Draws() => RunTop3NoWinStreaks(100_000);

	[Fact]
	public void SystemRandom_Top3NoWinStreaks_PerUser_100Draws() => RunTop3NoWinStreaksWithSystemRandom(100);

	[Fact]
	public void SystemRandom_Top3NoWinStreaks_PerUser_200Draws() => RunTop3NoWinStreaksWithSystemRandom(200);

	[Fact]
	public void SystemRandom_Top3NoWinStreaks_PerUser_300Draws() => RunTop3NoWinStreaksWithSystemRandom(300);

	[Fact]
	public void SystemRandom_Top3NoWinStreaks_PerUser_400Draws() => RunTop3NoWinStreaksWithSystemRandom(400);

	[Fact]
	public void SystemRandom_Top3NoWinStreaks_PerUser_500Draws() => RunTop3NoWinStreaksWithSystemRandom(500);

	[Fact]
	public void SystemRandom_Top3NoWinStreaks_PerUser_100000Draws() => RunTop3NoWinStreaksWithSystemRandom(100_000);

	/// <summary>
	/// 추첨 횟수가 적은(수백 회) 시나리오의 공통 본문. 당첨이 평균 수 회뿐이라
	/// 완료된 streak이 3개 미만일 수 있으므로 >=3은 단언하지 않는다.
	/// </summary>
	private void RunTop3NoWinStreaks(Int32 drawsPerUser)
	{
		const Int32 UserCount = 10;
		const Int32 WinDenominator = 100; // 당첨 확률 1% (Next(userId, 100) == 0)

		byte[] seed = Seed();

		output.WriteLine(
			$"사용자: {UserCount}명  추첨: {drawsPerUser:N0}회  " +
			$"당첨 확률: {100.0 / WinDenominator:F0}% (Next(userId, {WinDenominator}) == 0)");
		output.WriteLine(new string('-', 64));

		for (Int32 u = 0; u < UserCount; u++)
		{
			string userId = $"user-{u:D2}";

			// 상위 3개 streak만 내림차순으로 유지한다(네 번째로 작은 값은 버린다).
			Int32[] top3 = [0, 0, 0];
			Int32 currentStreak = 0;
			Int32 wins = 0;
			Int64 totalMisses = 0;

			for (Int64 tick = 1; tick <= drawsPerUser; tick++)
			{
				// Next(userId, WinDenominator)와 동일한 [0, WinDenominator) 값을 명시 seed로 결정론적으로 뽑는다.
				UInt32 draw = NextValue(seed, userId, tick, (UInt32)WinDenominator);

				if (draw == 0) // 당첨 → 진행 중이던 미당첨 streak 종료
				{
					wins++;
					RecordStreak(top3, currentStreak);
					currentStreak = 0;
				}
				else // 미당첨 → streak 증가
				{
					currentStreak++;
					totalMisses++;
				}
			}
			// 마지막까지 당첨 없이 끝난 잔여 streak도 후보로 기록한다.
			RecordStreak(top3, currentStreak);

			// 불변식: 모든 추첨은 당첨 또는 미당첨 중 정확히 하나다(seed 무관, 항상 성립).
			Assert.Equal(drawsPerUser, wins + totalMisses);
			// TOP 3는 내림차순이어야 한다.
			Assert.True(top3[0] >= top3[1] && top3[1] >= top3[2],
				$"{userId}: TOP3가 내림차순이 아님 [{top3[0]}, {top3[1]}, {top3[2]}]");
			// 추첨이 적어 완료 streak이 3개 미만일 수 있으므로 >=3은 단언하지 않는다.
			// 대신 최장 streak이 총 추첨 수를 넘지 않는지(당첨 0회면 drawsPerUser까지 가능)만 검증한다.
			Assert.InRange(top3[0], 0, drawsPerUser);

			output.WriteLine(
				$"{userId}  당첨 {wins,3}회  " +
				$"TOP3 연속 미당첨: [{top3[0],3}, {top3[1],3}, {top3[2],3}]");
		}
	}

	/// <summary>
	/// 위와 동일한 시나리오를 .NET 기본 랜덤 엔진(<see cref="Random"/>)으로 실행해 비교 기준선을 제공한다.
	/// AuditableRandom의 ChaCha20 기반 결과가 평범한 PRNG와 통계적으로 다르지 않음을 보여주는 것이 목적이다.
	/// 사용자별 고정 시드(SystemRandomSeedBase + u)로 결정론적·재현 가능하게 동작한다.
	/// </summary>
	private void RunTop3NoWinStreaksWithSystemRandom(Int32 drawsPerUser)
	{
		const Int32 UserCount = 10;
		const Int32 WinDenominator = 100; // 당첨 확률 1% (Next(WinDenominator) == 0)
		const Int32 SystemRandomSeedBase = 20260608;

		output.WriteLine(
			$"[System.Random] 사용자: {UserCount}명  추첨: {drawsPerUser:N0}회  " +
			$"당첨 확률: {100.0 / WinDenominator:F0}% (Next({WinDenominator}) == 0)");
		output.WriteLine(new string('-', 64));

		for (Int32 u = 0; u < UserCount; u++)
		{
			string userId = $"user-{u:D2}";
			Random random = new(SystemRandomSeedBase + u);

			Int32[] top3 = [0, 0, 0];
			Int32 currentStreak = 0;
			Int32 wins = 0;
			Int64 totalMisses = 0;

			for (Int64 tick = 1; tick <= drawsPerUser; tick++)
			{
				Int32 draw = random.Next(WinDenominator);

				if (draw == 0) // 당첨 → 진행 중이던 미당첨 streak 종료
				{
					wins++;
					RecordStreak(top3, currentStreak);
					currentStreak = 0;
				}
				else // 미당첨 → streak 증가
				{
					currentStreak++;
					totalMisses++;
				}
			}
			// 마지막까지 당첨 없이 끝난 잔여 streak도 후보로 기록한다.
			RecordStreak(top3, currentStreak);

			Assert.Equal(drawsPerUser, wins + totalMisses);
			Assert.True(top3[0] >= top3[1] && top3[1] >= top3[2],
				$"{userId}: TOP3가 내림차순이 아님 [{top3[0]}, {top3[1]}, {top3[2]}]");
			Assert.InRange(top3[0], 0, drawsPerUser);

			output.WriteLine(
				$"{userId}  당첨 {wins,3}회  " +
				$"TOP3 연속 미당첨: [{top3[0],3}, {top3[1],3}, {top3[2],3}]");
		}
	}

	/// <summary>
	/// 명시 seed 경로로 <c>Next(userId, maxExclusive)</c>와 동일한 <c>[0, maxExclusive)</c> 값을 뽑는다.
	/// 전역 <see cref="AuditableRandom.NextUInt32(string, UInt32, out Int64)"/>와 똑같은
	/// Lemire multiply-shift 거부표본추출(모듈로 편향 없음)을 한 블록의 16워드에 적용한다.
	/// Initialize() 없이 결정론적·재현 가능하게 실행되도록 seed와 tick을 직접 받는다.
	/// </summary>
	private static UInt32 NextValue(byte[] seed, string userId, Int64 tick, UInt32 maxExclusive)
	{
		Span<byte> block = stackalloc byte[64];
		while (true)
		{
			AuditableRandom.GetBlockChaCha20(seed, userId, tick, block);
			for (Int32 i = 0; i <= 64 - 4; i += 4)
			{
				UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i, 4));
				UInt64 product = (UInt64)raw * maxExclusive;
				UInt32 low = (UInt32)product;
				if (low >= maxExclusive || low >= unchecked(0u - maxExclusive) % maxExclusive)
					return (UInt32)(product >> 32);
			}
			// 한 블록의 16워드가 모두 거부될 확률은 사실상 0이지만, 전역 NextUInt32와 동형으로
			// 다음 tick에서 결정론적으로 재시도한다(벽시계 대신 tick+1로 진행).
			tick++;
		}
	}

	/// <summary>streak을 상위 3개 배열(내림차순)에 삽입한다. 최솟값 이하면 버린다.</summary>
	private static void RecordStreak(Int32[] top3, Int32 streak)
	{
		if (streak <= top3[2])
			return;

		if (streak >= top3[0])
		{
			top3[2] = top3[1];
			top3[1] = top3[0];
			top3[0] = streak;
		}
		else if (streak >= top3[1])
		{
			top3[2] = top3[1];
			top3[1] = streak;
		}
		else
		{
			top3[2] = streak;
		}
	}
}

/// <summary>
/// 전역 Initialize는 프로세스당 단 한 번만 성공하는 정적 상태라,
/// 이 어셈블리에서 Initialize를 호출하는 테스트는 이 하나뿐이어야 한다.
/// A3(재시작 간 tick 유일성)와 이중 초기화 방지를 함께 검증한다.
/// </summary>
public class InitializeTests
{
	[Fact]
	public void Initialize_FloorsTickAboveResume_AndRejectsSecondCall()
	{
		byte[] seed = new byte[32];
		RandomNumberGenerator.Fill(seed);

		// 현재 벽시계 tick보다 확실히 큰 값을 줘서 floor 로직을 실제로 검증한다.
		Int64 resume = DateTime.UtcNow.Ticks + TimeSpan.FromDays(3650).Ticks;
		Assert.False(AuditableRandom.IsInitialized); // Initialize 전에는 false
		AuditableRandom.Initialize(seed, resume);
		Assert.True(AuditableRandom.IsInitialized);  // Initialize 후에는 true

		// 이후 발급되는 tick은 resumeAfterTick을 반드시 초과해야 한다.
		AuditableRandom.Next("u", 1000, out Int64 tick);
		Assert.True(tick > resume, $"발급 tick({tick})이 resume({resume})을 초과해야 한다");

		// B2: 전역 캐시 키 경로(GetBlockChaCha20(userId, tick))의 출력이
		// 동일 시드의 명시 시드 경로와 바이트 단위로 일치해야 한다.
		byte[] viaCachedKey = AuditableRandom.GetBlockChaCha20("cmp-user", 777L);
		byte[] viaExplicitSeed = AuditableRandom.GetBlockChaCha20(seed, "cmp-user", 777L);
		Assert.Equal(viaExplicitSeed, viaCachedKey);

		// Shuffle은 인덱스 경계 버그가 없어야 한다(유효 순열 보존: 원소 손실/중복/범위 이탈 없음).
		List<Int32> items = Enumerable.Range(0, 200).ToList();
		AuditableRandom.Shuffle(items);
		Assert.Equal(Enumerable.Range(0, 200), items.OrderBy(x => x));

		// Span/배열 오버로드도 유효 순열을 보존해야 한다.
		Int32[] arr = Enumerable.Range(0, 300).ToArray();
		AuditableRandom.Shuffle(arr); // 배열 오버로드
		Assert.Equal(Enumerable.Range(0, 300), arr.OrderBy(x => x));

		Span<Int32> span = Enumerable.Range(0, 250).ToArray();
		AuditableRandom.Shuffle(span); // Span 오버로드
		Int32[] spanResult = span.ToArray();
		Assert.Equal(Enumerable.Range(0, 250), spanResult.OrderBy(x => x));

		// userId 바인딩 셔플 오버로드도 유효 순열을 보존해야 한다.
		List<Int32> userItems = Enumerable.Range(0, 150).ToList();
		AuditableRandom.Shuffle("shuffle-user", userItems);
		Assert.Equal(Enumerable.Range(0, 150), userItems.OrderBy(x => x));

		// Fill 라운드트립: 전역 경로로 생성한 임의 길이 keystream을
		// (seed, userId, tick)만으로 동일하게 재현한다(멀티블록 + 64바이트 미만 꼬리 포함).
		byte[] fillOut = new byte[150];
		AuditableRandom.Fill("fill-user", fillOut, out Int64 fillTick);
		Assert.True(fillTick > resume);
		byte[] fillRepro = new byte[150];
		AuditableRandom.Fill(seed, "fill-user", fillTick, fillRepro);
		Assert.Equal(fillRepro, fillOut);
		// 전역 키 재현 오버로드도 명시 seed 경로와 일치해야 한다.
		byte[] fillReproGlobal = new byte[150];
		AuditableRandom.Fill("fill-user", fillTick, fillReproGlobal);
		Assert.Equal(fillRepro, fillReproGlobal);

		// 부호 없는 범위 오버로드: 결과가 [min, max) 안에 있고 tick은 resume를 초과해야 한다.
		for (Int32 k = 0; k < 100; k++)
		{
			UInt32 u = AuditableRandom.NextUInt32("u", 1000u, 2000u, out Int64 uTick);
			Assert.InRange(u, 1000u, 1999u);
			Assert.True(uTick > resume);

			UInt64 ul = AuditableRandom.NextUInt64(500_000_000_000UL, 500_000_000_100UL);
			Assert.InRange(ul, 500_000_000_000UL, 500_000_000_099UL);
		}

		// 전 범위 오버로드: 거부 없이 블록 앞 4/8바이트를 그대로 쓰므로 저장된 tick만으로 직접 재현된다.
		UInt32 u32Full = AuditableRandom.NextUInt32("full-user", out Int64 u32Tick);
		Assert.True(u32Tick > resume);
		byte[] u32Block = AuditableRandom.GetBlockChaCha20(seed, "full-user", u32Tick);
		Assert.Equal(BinaryPrimitives.ReadUInt32BigEndian(u32Block), u32Full);

		UInt64 u64Full = AuditableRandom.NextUInt64("full-user", out Int64 u64Tick);
		Assert.True(u64Tick > resume);
		byte[] u64Block = AuditableRandom.GetBlockChaCha20(seed, "full-user", u64Tick);
		Assert.Equal(BinaryPrimitives.ReadUInt64BigEndian(u64Block), u64Full);

		// 무인자 오버로드(빈 userId)도 같은 계약을 따른다.
		UInt64 u64Empty = AuditableRandom.NextUInt64(out Int64 u64EmptyTick);
		byte[] u64EmptyBlock = AuditableRandom.GetBlockChaCha20(seed, string.Empty, u64EmptyTick);
		Assert.Equal(BinaryPrimitives.ReadUInt64BigEndian(u64EmptyBlock), u64Empty);

		// 부호 있는 전 범위 오버로드: 전 범위 부호 없는 추출의 비트 패턴을 2의 보수로 재해석한다.
		Int32 i32Full = AuditableRandom.NextInt32("full-user", out Int64 i32Tick);
		Assert.True(i32Tick > resume);
		byte[] i32Block = AuditableRandom.GetBlockChaCha20(seed, "full-user", i32Tick);
		Assert.Equal(unchecked((Int32)BinaryPrimitives.ReadUInt32BigEndian(i32Block)), i32Full);

		Int64 i64Full = AuditableRandom.NextInt64("full-user", out Int64 i64Tick);
		Assert.True(i64Tick > resume);
		byte[] i64Block = AuditableRandom.GetBlockChaCha20(seed, "full-user", i64Tick);
		Assert.Equal(unchecked((Int64)BinaryPrimitives.ReadUInt64BigEndian(i64Block)), i64Full);

		// 감사 라운드트립: Next/NextDouble로 뽑은 값을 (seed, userId, tick)만으로 동일하게 재현한다.
		// 저장된 seed로 재현하는 실제 감사 경로(전역 상태와 무관)를 검증한다 — 이 라이브러리의 핵심 계약.
		for (Int32 k = 0; k < 50; k++)
		{
			const UInt32 Max = 1000;
			Int32 drawn = AuditableRandom.Next("audit-user", (Int32)Max, out Int64 drawTick);

			// 재현: 저장한 seed로 동일 블록을 만들고 생성 당시와 동일한 Lemire 거부표본 스캔을 적용.
			byte[] block = AuditableRandom.GetBlockChaCha20(seed, "audit-user", drawTick);
			Int32 reproduced = -1;
			for (Int32 i = 0; i <= 64 - 4; i += 4)
			{
				UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block.AsSpan(i, 4));
				UInt64 product = (UInt64)raw * Max;
				UInt32 low = (UInt32)product;
				if (low >= Max || low >= unchecked(0u - Max) % Max)
				{
					reproduced = (Int32)(product >> 32);
					break;
				}
			}
			Assert.Equal(drawn, reproduced);

			// NextDouble은 거부 없이 앞 8바이트만 쓰므로 직접 재현된다.
			double dDrawn = AuditableRandom.NextDouble("audit-user", out Int64 dTick);
			byte[] dBlock = AuditableRandom.GetBlockChaCha20(seed, "audit-user", dTick);
			UInt64 dRaw = BinaryPrimitives.ReadUInt64BigEndian(dBlock);
			double dRepro = (dRaw >> 11) * (1.0 / (1UL << 53));
			Assert.Equal(dDrawn, dRepro);
		}

		// null userId는 ArgumentNullException(초기화 후 전역 경로의 WriteUserIdHash에서 검증).
		Assert.Throws<ArgumentNullException>(() => AuditableRandom.Next(null!, 10));

		// 두 번째 Initialize는 예외.
		Assert.Throws<InvalidOperationException>(() => AuditableRandom.Initialize(seed));
	}
}

/// <summary>
/// 부호 없는 범위 오버로드의 인자 검증. 검증은 RNG 상태 접근(FillBlock) 이전에 일어나므로
/// Initialize() 없이 독립 실행되며 전역 상태를 건드리지 않는다.
/// </summary>
public class UnsignedRangeValidationTests
{
	[Fact]
	public void NextUInt32_ZeroMax_Throws() =>
		Assert.Throws<ArgumentOutOfRangeException>(() => AuditableRandom.NextUInt32(0u));

	[Fact]
	public void NextUInt64_ZeroMax_Throws() =>
		Assert.Throws<ArgumentOutOfRangeException>(() => AuditableRandom.NextUInt64(0UL));

	[Fact]
	public void NextUInt32_MinNotLessThanMax_Throws() =>
		Assert.Throws<ArgumentOutOfRangeException>(() => AuditableRandom.NextUInt32(5u, 5u));

	[Fact]
	public void NextUInt64_MinNotLessThanMax_Throws() =>
		Assert.Throws<ArgumentOutOfRangeException>(() => AuditableRandom.NextUInt64(9UL, 8UL));

	[Fact]
	public void GetBlockChaCha20_NullUserId_Throws() =>
		// 명시 seed 경로는 Initialize와 무관하게 WriteUserIdHash에서 null을 거부한다.
		Assert.Throws<ArgumentNullException>(() => AuditableRandom.GetBlockChaCha20(new byte[32], null!, 1L));

	[Fact]
	public void GetBlockChaCha20_NegativeTick_Throws() =>
		// 생성 경로는 음수 tick을 발급하지 않으므로 재현 경로의 음수는 손상된 감사 로그다.
		Assert.Throws<ArgumentOutOfRangeException>(() => AuditableRandom.GetBlockChaCha20(new byte[32], "u", -1L));
}

/// <summary>
/// Initialize 인자 검증. 검증 실패는 1회 한정 초기화 기회를 소모하지 않아야 하므로
/// (검증이 CAS보다 먼저 수행됨) 전역 초기화 여부와 무관하게 독립 실행된다.
/// </summary>
public class InitializeValidationTests
{
	[Fact]
	public void InvalidArguments_Throw_WithoutConsumingInit()
	{
		Assert.Throws<ArgumentNullException>(() => AuditableRandom.Initialize((byte[])null!));
		Assert.Throws<ArgumentException>(() => AuditableRandom.Initialize(new byte[31]));          // 배열 오버로드
		Assert.Throws<ArgumentException>(() => AuditableRandom.Initialize(new byte[33].AsSpan())); // Span 오버로드
		Assert.Throws<ArgumentOutOfRangeException>(() => AuditableRandom.Initialize(new byte[32].AsSpan(), -1L));
	}
}

/// <summary>
/// Lemire multiply-shift 축소(TryReduce)의 경계 동작을 고정한다.
/// 순수 함수라 전역 상태와 무관하게 독립 실행된다.
/// </summary>
public class TryReduceTests
{
	[Fact]
	public void Range1_AlwaysAcceptsAsZero()
	{
		foreach (UInt32 raw in new UInt32[] { 0u, 1u, 12345u, UInt32.MaxValue })
		{
			Assert.True(AuditableRandom.TryReduce(raw, 1u, out UInt32 v));
			Assert.Equal(0u, v);
		}
		foreach (UInt64 raw in new UInt64[] { 0UL, 1UL, 12345UL, UInt64.MaxValue })
		{
			Assert.True(AuditableRandom.TryReduce(raw, 1UL, out UInt64 v));
			Assert.Equal(0UL, v);
		}
	}

	[Fact]
	public void PowerOfTwoRange_NeverRejects_MapsToHighBits()
	{
		// 2^k 범위는 threshold = 2^N mod 2^k = 0이라 어떤 raw도 거부되지 않고 상위 비트로 사상된다.
		foreach (UInt32 raw in new UInt32[] { 0u, 1u, 0x7FFFFFFFu, 0x80000000u, UInt32.MaxValue })
		{
			Assert.True(AuditableRandom.TryReduce(raw, 1u << 31, out UInt32 v));
			Assert.Equal(raw >> 1, v);
		}
		foreach (UInt64 raw in new UInt64[] { 0UL, 1UL, UInt64.MaxValue })
		{
			Assert.True(AuditableRandom.TryReduce(raw, 1UL << 63, out UInt64 v));
			Assert.Equal(raw >> 1, v);
		}
	}

	[Fact]
	public void RejectionBoundary_Range3()
	{
		// range=3: threshold = 2^32 mod 3 = 1. product 하위 워드(low)가 1 미만인 raw만 거부된다.
		Assert.False(AuditableRandom.TryReduce(0u, 3u, out _));          // low=0 → 거부
		Assert.True(AuditableRandom.TryReduce(1u, 3u, out UInt32 v32));  // low=3 → 수락
		Assert.Equal(0u, v32);
		Assert.True(AuditableRandom.TryReduce(UInt32.MaxValue, 3u, out v32));
		Assert.Equal(2u, v32);

		// 64비트도 threshold = 2^64 mod 3 = 1로 동일한 경계.
		Assert.False(AuditableRandom.TryReduce(0UL, 3UL, out _));
		Assert.True(AuditableRandom.TryReduce(1UL, 3UL, out UInt64 v64));
		Assert.Equal(0UL, v64);
		Assert.True(AuditableRandom.TryReduce(UInt64.MaxValue, 3UL, out v64));
		Assert.Equal(2UL, v64);
	}

	[Fact]
	public void AcceptedValues_AlwaysInRange()
	{
		Random rng = new(20260612); // 결정론적 재현을 위한 고정 시드
		UInt32[] ranges32 = [2u, 3u, 7u, 100u, 1000u, 1u << 20, UInt32.MaxValue];
		UInt64[] ranges64 = [2UL, 3UL, 1000UL, 1UL << 40, UInt64.MaxValue];
		for (Int32 k = 0; k < 10_000; k++)
		{
			UInt32 raw32 = (UInt32)rng.NextInt64(0, 1L << 32);
			foreach (UInt32 range in ranges32)
			{
				if (AuditableRandom.TryReduce(raw32, range, out UInt32 v))
					Assert.True(v < range, $"raw={raw32} range={range} value={v}");
			}

			UInt64 raw64 = (UInt64)rng.NextInt64() ^ ((UInt64)rng.NextInt64() << 32);
			foreach (UInt64 range in ranges64)
			{
				if (AuditableRandom.TryReduce(raw64, range, out UInt64 v))
					Assert.True(v < range, $"raw={raw64} range={range} value={v}");
			}
		}
	}
}

/// <summary>
/// 임의 길이 Fill의 멀티블록 규약(블록당 counter+1, 접두 일관성)을 검증한다.
/// 명시 seed 경로라 Initialize() 없이 독립 실행된다.
/// </summary>
public class FillTests
{
	private static byte[] Seed()
	{
		byte[] s = new byte[32];
		for (Int32 i = 0; i < 32; i++)
			s[i] = (byte)(0x90 + i);
		return s;
	}

	[Fact]
	public void FirstBlock_MatchesGetBlock()
	{
		byte[] seed = Seed();
		byte[] block = AuditableRandom.GetBlockChaCha20(seed, "fill-user", 42L);

		byte[] filled = new byte[200];
		AuditableRandom.Fill(seed, "fill-user", 42L, filled);

		Assert.Equal(block, filled[..64]);
		// 두 번째 블록(counter+1)은 첫 블록과 달라야 한다.
		Assert.NotEqual(block, filled[64..128]);
	}

	[Fact]
	public void ShorterLength_IsPrefixOfLonger()
	{
		byte[] seed = Seed();
		byte[] longOut = new byte[300];
		AuditableRandom.Fill(seed, "fill-user", 7L, longOut);

		byte[] shortOut = new byte[100]; // 64바이트 미만 꼬리 경로 포함
		AuditableRandom.Fill(seed, "fill-user", 7L, shortOut);

		Assert.Equal(longOut[..100], shortOut);
	}

	[Fact]
	public void NegativeTick_Throws() =>
		Assert.Throws<ArgumentOutOfRangeException>(() =>
			AuditableRandom.Fill(Seed(), "u", -1L, new byte[10]));
}

/// <summary>
/// 무할당 Span 출력 오버로드 검증. byte[] 오버로드와 바이트 단위로 일치하고, 너무 작은 버퍼는 거부해야 한다.
/// 명시 seed 경로라 Initialize() 없이 독립 실행된다.
/// </summary>
public class SpanBlockOverloadTests
{
	private static byte[] Seed()
	{
		byte[] s = new byte[32];
		for (Int32 i = 0; i < 32; i++)
			s[i] = (byte)(0xA0 + i);
		return s;
	}

	[Fact]
	public void SpanOverload_MatchesByteArrayOverload()
	{
		byte[] seed = Seed();
		byte[] viaArray = AuditableRandom.GetBlockChaCha20(seed, "u", 42L);

		Span<byte> viaSpan = stackalloc byte[64];
		AuditableRandom.GetBlockChaCha20(seed, "u", 42L, viaSpan);

		Assert.Equal(viaArray, viaSpan.ToArray());
	}

	[Fact]
	public void SpanOverload_TooSmallDestination_Throws() =>
		Assert.Throws<ArgumentException>(() =>
			AuditableRandom.GetBlockChaCha20(Seed(), "u", 42L, new byte[63]));
}
