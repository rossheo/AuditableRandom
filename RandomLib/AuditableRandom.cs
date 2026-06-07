using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Hashing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace RandomLib;

/// <summary>
/// ChaCha20 기반 감사 가능(재현 가능) 난수 생성기. 각 추출은 고유 <c>tick</c>을 함께 산출하며,
/// 등록된 seed와 <c>(userId, tick)</c>만으로 keystream을 바이트 단위로 재현할 수 있다.
/// 전역 seed 경로를 쓰기 전 <see cref="Initialize(byte[])"/>를 프로세스당 한 번 호출해야 한다.
/// </summary>
/// <remarks>
/// 정수·부동소수 메서드는 공통 오버로드 규약을 따른다.
/// <list type="bullet">
/// <item><description>userId 생략 시 빈 사용자, 지정 시 결과를 해당 사용자에 바인딩한다(null이면 <see cref="ArgumentNullException"/>).</description></item>
/// <item><description><c>out Int64 tick</c> 생략 시 tick을 버리고, 지정 시 감사 로그 저장용 tick을 받는다.</description></item>
/// <item><description>정수 범위는 <c>[0, maxExclusive)</c> 또는 <c>[minInclusive, maxExclusive)</c>이며 모듈로 편향이 없다.</description></item>
/// <item><description>잘못된 범위(max ≤ 0, min ≥ max 등)는 <see cref="ArgumentOutOfRangeException"/>을 던진다.</description></item>
/// </list>
/// 정적 메서드는 스레드 안전하다(tick 발급은 원자적).
/// </remarks>
public static class AuditableRandom
{
	private const Int32 KeySize = 32;
	private const Int32 BlockSize = 64;

	// tick의 기본 베이스로 프로세스 시작 시각(UTC)을 쓰고, 이후 증분은 고해상도 타임스탬프로 단조 증가시킨다.
	// 단, system clock은 뒤로 갈 수 있어 재시작 간 tick 구간 분리는 보장되지 않는다.
	// 같은 seed를 재사용할 때의 재시작 간 유일성은 Initialize(seed, resumeAfterTick)로 보강해야 한다.
	private static readonly Int64 _tickBase = DateTime.UtcNow.Ticks;
	private static readonly Int64 _startTimestamp = Stopwatch.GetTimestamp();
	// 타임스탬프 1틱을 100ns 단위(DateTime.Ticks)로 환산하는 계수.
	private static readonly double _tickScale = 10_000_000.0 / Stopwatch.Frequency;
	// 빈 userId는 매번 계산하지 않도록 해시를 사전 계산해 둔다.
	private static readonly UInt64 _emptyUserIdHash = XxHash3.HashToUInt64(ReadOnlySpan<byte>.Empty);
	private static Int64 _lastTick = 0;
	private static Int32 _initialized;
	private static byte[]? _seed;
	// 전역 seed의 키 워드(s4..s11)를 미리 Vector128로 변환해 둔다(매 블록의 LE 읽기 제거).
	private static Vector128<UInt32> _keyVecLow;
	private static Vector128<UInt32> _keyVecHigh;

	/// <summary>
	/// ChaCha20 seed(32바이트)를 등록한다. 프로세스 수명 동안 한 번만 호출할 수 있다.
	/// </summary>
	/// <exception cref="ArgumentException">seed 길이가 32바이트가 아닌 경우</exception>
	/// <exception cref="InvalidOperationException">이미 초기화된 경우</exception>
	public static void Initialize(byte[] seed) =>
		Initialize(seed, 0);

	/// <summary>
	/// ChaCha20 seed(32바이트)를 등록한다. 프로세스 수명 동안 한 번만 호출할 수 있다.
	/// </summary>
	/// <param name="seed">32바이트 seed</param>
	/// <param name="resumeAfterTick">
	/// 이전 실행에서 발급한 마지막 tick. 이후 발급되는 모든 tick이 이 값을 반드시 초과하도록 보장해,
	/// 같은 seed를 재사용하는 재시작 간에 (seed, nonce) 재사용을 방지한다.
	/// 효과를 보려면 호출자가 발급된 tick의 최댓값(Next/GetBlock의 out tick)을 내구성 있게 저장했다가
	/// 다음 시작 시 그 값을 넘겨야 한다. 0이면 system clock 기준만 사용하며 재시작 간 유일성은 보장되지 않는다.
	/// </param>
	/// <exception cref="ArgumentException">seed 길이가 32바이트가 아닌 경우</exception>
	/// <exception cref="ArgumentOutOfRangeException">resumeAfterTick이 음수인 경우</exception>
	/// <exception cref="InvalidOperationException">이미 초기화된 경우</exception>
	public static void Initialize(byte[] seed, Int64 resumeAfterTick)
	{
		ArgumentNullException.ThrowIfNull(seed);
		if (seed.Length != KeySize)
		{
			throw new ArgumentException(
				$"seed는 {KeySize}바이트여야 합니다. (실제: {seed.Length}바이트)",
				nameof(seed));
		}
		ArgumentOutOfRangeException.ThrowIfNegative(resumeAfterTick);

		if (Interlocked.CompareExchange(ref _initialized, 1, 0) != 0)
			throw new InvalidOperationException("AuditableRandom은 이미 초기화되었습니다.");

		// 이후 발급되는 tick이 resumeAfterTick을 반드시 초과하도록 바닥값을 끌어올린다.
		// 시드 공개보다 먼저 수행해, 시드를 읽는 Next가 항상 끌어올려진 tick을 보도록 한다.
		InterlockedMax(ref _lastTick, resumeAfterTick);

		// 호출자가 이후 배열을 변경해도 RNG에 영향이 없도록 방어적 복사본을 보관한다.
		byte[] clone = (byte[])seed.Clone();

		// 키 워드 벡터를 _seed 공개 전에 채워, 시드를 본 스레드가 항상 키 벡터도 보도록 한다.
		_keyVecLow = Vector128.Create<byte>(clone.AsSpan(0, 16)).AsUInt32();
		_keyVecHigh = Vector128.Create<byte>(clone.AsSpan(16, 16)).AsUInt32();

		Volatile.Write(ref _seed, clone);
	}

	/// <summary>
	/// <see cref="Initialize(byte[])"/>가 호출되어 seed가 등록되었는지 여부.
	/// 전역 seed 경로(Next/NextDouble/Shuffle 등)는 등록 후에만 사용할 수 있다.
	/// </summary>
	public static bool IsInitialized => Volatile.Read(ref _seed) is not null;

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 정수를 뽑는다.</summary>
	public static Int32 Next(Int32 maxExclusive) =>
		Next(string.Empty, maxExclusive);

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static Int32 Next(Int32 maxExclusive, out Int64 tick) =>
		Next(string.Empty, maxExclusive, out tick);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 정수를 뽑는다.</summary>
	public static Int32 Next(Int32 minInclusive, Int32 maxExclusive) =>
		Next(string.Empty, minInclusive, maxExclusive);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static Int32 Next(Int32 minInclusive, Int32 maxExclusive, out Int64 tick) =>
		Next(string.Empty, minInclusive, maxExclusive, out tick);

	/// <summary>userId에 바인딩해 <c>[0, maxExclusive)</c> 정수를 뽑는다.</summary>
	public static Int32 Next(string userId, Int32 maxExclusive) =>
		Next(userId, maxExclusive, out _);

	/// <summary>userId에 바인딩해 <c>[0, maxExclusive)</c> 정수를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxExclusive"/>가 0 이하인 경우</exception>
	public static Int32 Next(string userId, Int32 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxExclusive);
		return (Int32)NextUInt32(userId, (UInt32)maxExclusive, out tick);
	}

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 정수를 뽑는다.</summary>
	public static Int32 Next(string userId, Int32 minInclusive, Int32 maxExclusive) =>
		Next(userId, minInclusive, maxExclusive, out _);

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 정수를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="minInclusive"/>가 <paramref name="maxExclusive"/> 이상인 경우</exception>
	public static Int32 Next(string userId, Int32 minInclusive, Int32 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(minInclusive, maxExclusive);
		// Int64로 폭을 넓혀 (max - min), (min + value) 모두 오버플로 없이 계산한다.
		UInt32 range = (UInt32)((Int64)maxExclusive - minInclusive);
		UInt32 value = NextUInt32(userId, range, out tick);
		return (Int32)((Int64)minInclusive + value);
	}

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 64비트 정수를 뽑는다.</summary>
	public static Int64 NextInt64(Int64 maxExclusive) =>
		NextInt64(string.Empty, maxExclusive);

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 64비트 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static Int64 NextInt64(Int64 maxExclusive, out Int64 tick) =>
		NextInt64(string.Empty, maxExclusive, out tick);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 64비트 정수를 뽑는다.</summary>
	public static Int64 NextInt64(Int64 minInclusive, Int64 maxExclusive) =>
		NextInt64(string.Empty, minInclusive, maxExclusive);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 64비트 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static Int64 NextInt64(Int64 minInclusive, Int64 maxExclusive, out Int64 tick) =>
		NextInt64(string.Empty, minInclusive, maxExclusive, out tick);

	/// <summary>userId에 바인딩해 <c>[0, maxExclusive)</c> 64비트 정수를 뽑는다.</summary>
	public static Int64 NextInt64(string userId, Int64 maxExclusive) =>
		NextInt64(userId, maxExclusive, out _);

	/// <summary>userId에 바인딩해 <c>[0, maxExclusive)</c> 64비트 정수를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxExclusive"/>가 0 이하인 경우</exception>
	public static Int64 NextInt64(string userId, Int64 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxExclusive);
		return (Int64)NextUInt64(userId, (UInt64)maxExclusive, out tick);
	}

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 64비트 정수를 뽑는다.</summary>
	public static Int64 NextInt64(string userId, Int64 minInclusive, Int64 maxExclusive) =>
		NextInt64(userId, minInclusive, maxExclusive, out _);

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 64비트 정수를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="minInclusive"/>가 <paramref name="maxExclusive"/> 이상인 경우</exception>
	public static Int64 NextInt64(string userId, Int64 minInclusive, Int64 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(minInclusive, maxExclusive);
		// 차이가 Int64 범위를 넘어도(2^64-1까지) 2의 보수 연산으로 정확한 폭을 얻는다.
		UInt64 range = unchecked((UInt64)(maxExclusive - minInclusive));
		UInt64 value = NextUInt64(userId, range, out tick);
		return unchecked(minInclusive + (Int64)value);
	}

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 부호 없는 정수를 뽑는다.</summary>
	public static UInt32 NextUInt32(UInt32 maxExclusive) =>
		NextUInt32(string.Empty, maxExclusive, out _);

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 부호 없는 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static UInt32 NextUInt32(UInt32 maxExclusive, out Int64 tick) =>
		NextUInt32(string.Empty, maxExclusive, out tick);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 부호 없는 정수를 뽑는다.</summary>
	public static UInt32 NextUInt32(UInt32 minInclusive, UInt32 maxExclusive) =>
		NextUInt32(string.Empty, minInclusive, maxExclusive, out _);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 부호 없는 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static UInt32 NextUInt32(UInt32 minInclusive, UInt32 maxExclusive, out Int64 tick) =>
		NextUInt32(string.Empty, minInclusive, maxExclusive, out tick);

	/// <summary>userId에 바인딩해 <c>[0, maxExclusive)</c> 부호 없는 정수를 뽑는다.</summary>
	public static UInt32 NextUInt32(string userId, UInt32 maxExclusive) =>
		NextUInt32(userId, maxExclusive, out _);

	/// <summary>
	/// userId에 바인딩해 <c>[0, maxExclusive)</c> 부호 없는 정수를 모듈로 편향 없이 뽑고 감사용 <paramref name="tick"/>을 받는다.
	/// 한 블록의 모든 워드가 거부되면 새 블록(새 틱)으로 재시도한다.
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxExclusive"/>가 0인 경우</exception>
	public static UInt32 NextUInt32(string userId, UInt32 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfZero(maxExclusive);
		UInt32 limit = (UInt32.MaxValue / maxExclusive) * maxExclusive;
		Span<byte> block = stackalloc byte[BlockSize];
		while (true)
		{
			tick = GetUniqueExecutionTicks();
			FillBlock(userId, tick, block);
			for (Int32 i = 0; i <= BlockSize - 4; i += 4)
			{
				UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(i, 4));
				if (raw < limit)
					return raw % maxExclusive;
			}
		}
	}

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 부호 없는 정수를 뽑는다.</summary>
	public static UInt32 NextUInt32(string userId, UInt32 minInclusive, UInt32 maxExclusive) =>
		NextUInt32(userId, minInclusive, maxExclusive, out _);

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 부호 없는 정수를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="minInclusive"/>가 <paramref name="maxExclusive"/> 이상인 경우</exception>
	public static UInt32 NextUInt32(string userId, UInt32 minInclusive, UInt32 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(minInclusive, maxExclusive);
		// max > min이 보장되어 폭은 [1, 2^32-1]; min + value는 max-1을 넘지 않아 오버플로가 없다.
		UInt32 range = maxExclusive - minInclusive;
		UInt32 value = NextUInt32(userId, range, out tick);
		return minInclusive + value;
	}

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 부호 없는 64비트 정수를 뽑는다.</summary>
	public static UInt64 NextUInt64(UInt64 maxExclusive) =>
		NextUInt64(string.Empty, maxExclusive, out _);

	/// <summary>빈 사용자로 <c>[0, maxExclusive)</c> 부호 없는 64비트 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static UInt64 NextUInt64(UInt64 maxExclusive, out Int64 tick) =>
		NextUInt64(string.Empty, maxExclusive, out tick);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 부호 없는 64비트 정수를 뽑는다.</summary>
	public static UInt64 NextUInt64(UInt64 minInclusive, UInt64 maxExclusive) =>
		NextUInt64(string.Empty, minInclusive, maxExclusive, out _);

	/// <summary>빈 사용자로 <c>[minInclusive, maxExclusive)</c> 부호 없는 64비트 정수를 뽑고 감사용 tick을 받는다.</summary>
	public static UInt64 NextUInt64(UInt64 minInclusive, UInt64 maxExclusive, out Int64 tick) =>
		NextUInt64(string.Empty, minInclusive, maxExclusive, out tick);

	/// <summary>userId에 바인딩해 <c>[0, maxExclusive)</c> 부호 없는 64비트 정수를 뽑는다.</summary>
	public static UInt64 NextUInt64(string userId, UInt64 maxExclusive) =>
		NextUInt64(userId, maxExclusive, out _);

	/// <summary>
	/// userId에 바인딩해 <c>[0, maxExclusive)</c> 부호 없는 64비트 정수를 모듈로 편향 없이 뽑고 감사용 <paramref name="tick"/>을 받는다.
	/// 한 블록의 모든 워드가 거부되면 새 블록(새 틱)으로 재시도한다.
	/// </summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxExclusive"/>가 0인 경우</exception>
	public static UInt64 NextUInt64(string userId, UInt64 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfZero(maxExclusive);
		UInt64 limit = (UInt64.MaxValue / maxExclusive) * maxExclusive;
		Span<byte> block = stackalloc byte[BlockSize];
		while (true)
		{
			tick = GetUniqueExecutionTicks();
			FillBlock(userId, tick, block);
			for (Int32 i = 0; i <= BlockSize - 8; i += 8)
			{
				UInt64 raw = BinaryPrimitives.ReadUInt64BigEndian(block.Slice(i, 8));
				if (raw < limit)
					return raw % maxExclusive;
			}
		}
	}

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 부호 없는 64비트 정수를 뽑는다.</summary>
	public static UInt64 NextUInt64(string userId, UInt64 minInclusive, UInt64 maxExclusive) =>
		NextUInt64(userId, minInclusive, maxExclusive, out _);

	/// <summary>userId에 바인딩해 <c>[minInclusive, maxExclusive)</c> 부호 없는 64비트 정수를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="minInclusive"/>가 <paramref name="maxExclusive"/> 이상인 경우</exception>
	public static UInt64 NextUInt64(string userId, UInt64 minInclusive, UInt64 maxExclusive, out Int64 tick)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThanOrEqual(minInclusive, maxExclusive);
		// max > min이 보장되어 폭은 [1, 2^64-1]; min + value는 max-1을 넘지 않아 오버플로가 없다.
		UInt64 range = maxExclusive - minInclusive;
		UInt64 value = NextUInt64(userId, range, out tick);
		return minInclusive + value;
	}

	/// <summary>빈 사용자로 <c>[0, 1)</c> 배정밀도 실수를 뽑는다.</summary>
	public static double NextDouble() =>
		NextDouble(string.Empty, out _);

	/// <summary>빈 사용자로 <c>[0, 1)</c> 배정밀도 실수를 뽑고 감사용 tick을 받는다.</summary>
	public static double NextDouble(out Int64 tick) =>
		NextDouble(string.Empty, out tick);

	/// <summary>userId에 바인딩해 <c>[0, 1)</c> 배정밀도 실수를 뽑는다.</summary>
	public static double NextDouble(string userId) =>
		NextDouble(userId, out _);

	/// <summary>userId에 바인딩해 <c>[0, 1)</c> 배정밀도 실수(53비트 해상도)를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	public static double NextDouble(string userId, out Int64 tick)
	{
		Span<byte> block = stackalloc byte[BlockSize];
		tick = GetUniqueExecutionTicks();
		FillBlock(userId, tick, block);
		UInt64 raw = BinaryPrimitives.ReadUInt64BigEndian(block[..8]);
		return (raw >> 11) * (1.0 / (1UL << 53));
	}

	/// <summary>빈 사용자로 <c>[0, 1)</c> 단정밀도 실수를 뽑는다.</summary>
	public static float NextSingle() =>
		NextSingle(string.Empty, out _);

	/// <summary>빈 사용자로 <c>[0, 1)</c> 단정밀도 실수를 뽑고 감사용 tick을 받는다.</summary>
	public static float NextSingle(out Int64 tick) =>
		NextSingle(string.Empty, out tick);

	/// <summary>userId에 바인딩해 <c>[0, 1)</c> 단정밀도 실수를 뽑는다.</summary>
	public static float NextSingle(string userId) =>
		NextSingle(userId, out _);

	/// <summary>userId에 바인딩해 <c>[0, 1)</c> 단정밀도 실수(24비트 해상도)를 뽑고 감사용 <paramref name="tick"/>을 받는다.</summary>
	public static float NextSingle(string userId, out Int64 tick)
	{
		Span<byte> block = stackalloc byte[BlockSize];
		tick = GetUniqueExecutionTicks();
		FillBlock(userId, tick, block);
		UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block[..4]);
		return (raw >> 9) * (1.0f / (1U << 23));
	}

	/// <summary>
	/// Fisher-Yates 셔플. 셔플 결과는 감사/재현 대상이 아니므로(틱을 저장하지 않음)
	/// 한 ChaCha20 블록(16워드)을 여러 스왑에 재사용해 블록 생성을 줄인다.
	/// </summary>
	public static void Shuffle<T>(IList<T> list)
	{
		ArgumentNullException.ThrowIfNull(list);
		Int32 n = list.Count;
		if (n <= 1)
			return;

		Span<byte> block = stackalloc byte[BlockSize];
		Int32 pos = BlockSize; // BlockSize면 다음 워드 요청 시 새 블록(새 틱)으로 채운다.

		for (Int32 i = n - 1; i > 0; --i)
		{
			Int32 j = (Int32)NextShuffleIndex((UInt32)(i + 1), block, ref pos);
			(list[i], list[j]) = (list[j], list[i]);
		}
	}

	/// <summary>
	/// <see cref="Shuffle{T}(IList{T})"/>의 Span 오버로드. 인터페이스 가상 호출이 없어 더 빠르며,
	/// 배열·List(<see cref="System.Runtime.InteropServices.CollectionsMarshal.AsSpan{T}(List{T})"/>) 등에 직접 적용할 수 있다.
	/// </summary>
	public static void Shuffle<T>(Span<T> span)
	{
		Int32 n = span.Length;
		if (n <= 1)
			return;

		Span<byte> block = stackalloc byte[BlockSize];
		Int32 pos = BlockSize;

		for (Int32 i = n - 1; i > 0; --i)
		{
			Int32 j = (Int32)NextShuffleIndex((UInt32)(i + 1), block, ref pos);
			(span[i], span[j]) = (span[j], span[i]);
		}
	}

	/// <summary>
	/// <see cref="Shuffle{T}(Span{T})"/>의 배열 오버로드. 배열 인자가 IList/Span 오버로드 사이에서
	/// 모호해지지 않도록 명시적으로 제공하며, null을 거부한다.
	/// </summary>
	public static void Shuffle<T>(T[] array)
	{
		ArgumentNullException.ThrowIfNull(array);
		Shuffle(array.AsSpan());
	}

	/// <summary>
	/// 셔플용 [0, range) 거부표본 인덱스를 뽑는다. 64바이트 블록 버퍼(block)와 위치(pos)를
	/// 여러 스왑에 재사용하며, 소진/거부 시 새 틱으로 블록을 다시 채운다.
	/// </summary>
	private static UInt32 NextShuffleIndex(UInt32 range, Span<byte> block, ref Int32 pos)
	{
		UInt32 limit = (UInt32.MaxValue / range) * range;

		// NextUInt32와 동일한 거부 표본추출(모듈로 편향 없음). 거부/소진 시 새 워드로 진행.
		while (true)
		{
			if (pos > BlockSize - 4)
			{
				FillBlock(string.Empty, GetUniqueExecutionTicks(), block);
				pos = 0;
			}

			UInt32 raw = BinaryPrimitives.ReadUInt32BigEndian(block.Slice(pos, 4));
			pos += 4;
			if (raw < limit)
				return raw % range;
		}
	}

	/// <summary>
	/// ChaCha20으로 64바이트 keystream 블록을 새 틱으로 생성해 반환한다.
	/// 동일한 seed에서 동일한 (tick, userId) 조합으로 결과를 완벽하게 재현할 수 있다.
	/// </summary>
	/// <param name="userId">ApplicationUser.Id 원본값</param>
	/// <param name="tick">생성에 사용된 고유 틱 — Audit Log 저장용</param>
	/// <exception cref="InvalidOperationException">Initialize()가 호출되지 않은 경우</exception>
	public static byte[] GetBlockChaCha20(string userId, out Int64 tick)
	{
		byte[] block = new byte[BlockSize];
		GetBlockChaCha20(userId, block, out tick);
		return block;
	}

	/// <summary>
	/// 64바이트 keystream 블록을 새 틱으로 생성해 <paramref name="destination"/>에 채운다(무할당).
	/// 버퍼를 재사용할 수 있어 반복 생성에 유리하다.
	/// </summary>
	/// <param name="userId">ApplicationUser.Id 원본값</param>
	/// <param name="destination">최소 64바이트 출력 버퍼</param>
	/// <param name="tick">생성에 사용된 고유 틱 — Audit Log 저장용</param>
	/// <exception cref="ArgumentException">destination이 64바이트 미만인 경우</exception>
	/// <exception cref="InvalidOperationException">Initialize()가 호출되지 않은 경우</exception>
	public static void GetBlockChaCha20(string userId, Span<byte> destination, out Int64 tick)
	{
		ThrowIfBlockBufferTooSmall(destination);
		tick = GetUniqueExecutionTicks();
		FillBlock(userId, tick, destination);
	}

	/// <summary>
	/// 저장된 (tick, userId)로 keystream 블록을 결정론적으로 재생성한다(Audit 재현용).
	/// 생성 당시와 동일한 seed가 등록되어 있어야 같은 결과가 나온다.
	/// </summary>
	/// <param name="userId">생성 당시 사용한 ApplicationUser.Id 원본값</param>
	/// <param name="tick">생성 당시 기록된 UniqueExecutionTick 값</param>
	/// <exception cref="InvalidOperationException">Initialize()가 호출되지 않은 경우</exception>
	public static byte[] GetBlockChaCha20(string userId, Int64 tick)
	{
		byte[] block = new byte[BlockSize];
		GetBlockChaCha20(userId, tick, block);
		return block;
	}

	/// <summary>
	/// 저장된 (tick, userId)로 keystream 블록을 <paramref name="destination"/>에 결정론적으로 재생성한다(무할당, Audit 재현용).
	/// </summary>
	/// <param name="userId">생성 당시 사용한 ApplicationUser.Id 원본값</param>
	/// <param name="tick">생성 당시 기록된 UniqueExecutionTick 값</param>
	/// <param name="destination">최소 64바이트 출력 버퍼</param>
	/// <exception cref="ArgumentException">destination이 64바이트 미만인 경우</exception>
	/// <exception cref="InvalidOperationException">Initialize()가 호출되지 않은 경우</exception>
	public static void GetBlockChaCha20(string userId, Int64 tick, Span<byte> destination)
	{
		ThrowIfBlockBufferTooSmall(destination);
		FillBlock(userId, tick, destination);
	}

	/// <summary>
	/// 명시한 seed로 keystream 블록을 결정론적으로 재생성한다(과거 시드 재현용).
	/// 전역 _seed와 무관하게 동작하므로 Initialize() 없이도 호출할 수 있다.
	/// </summary>
	/// <param name="seed">생성 당시 사용한 32바이트 seed</param>
	/// <param name="userId">생성 당시 사용한 ApplicationUser.Id 원본값</param>
	/// <param name="tick">생성 당시 기록된 UniqueExecutionTick 값</param>
	/// <exception cref="ArgumentException">seed 길이가 32바이트가 아닌 경우</exception>
	public static byte[] GetBlockChaCha20(byte[] seed, string userId, Int64 tick)
	{
		byte[] block = new byte[BlockSize];
		GetBlockChaCha20(seed, userId, tick, block);
		return block;
	}

	/// <summary>
	/// 명시한 seed로 keystream 블록을 <paramref name="destination"/>에 결정론적으로 재생성한다(무할당, 과거 시드 재현용).
	/// 전역 _seed와 무관하게 동작하므로 Initialize() 없이도 호출할 수 있다.
	/// </summary>
	/// <param name="seed">생성 당시 사용한 32바이트 seed</param>
	/// <param name="userId">생성 당시 사용한 ApplicationUser.Id 원본값</param>
	/// <param name="tick">생성 당시 기록된 UniqueExecutionTick 값</param>
	/// <param name="destination">최소 64바이트 출력 버퍼</param>
	/// <exception cref="ArgumentException">seed가 32바이트가 아니거나 destination이 64바이트 미만인 경우</exception>
	public static void GetBlockChaCha20(byte[] seed, string userId, Int64 tick, Span<byte> destination)
	{
		ArgumentNullException.ThrowIfNull(seed);
		if (seed.Length != KeySize)
		{
			throw new ArgumentException(
				$"seed는 {KeySize}바이트여야 합니다. (실제: {seed.Length}바이트)",
				nameof(seed));
		}
		ThrowIfBlockBufferTooSmall(destination);
		FillBlock(seed, userId, tick, destination);
	}

	private static void ThrowIfBlockBufferTooSmall(Span<byte> destination)
	{
		if (destination.Length < BlockSize)
		{
			throw new ArgumentException(
				$"destination은 최소 {BlockSize}바이트여야 합니다. (실제: {destination.Length}바이트)",
				nameof(destination));
		}
	}

	/// <summary>
	/// (tick, userId)로 nonce를 구성해 destination(최소 64바이트)에 keystream을 채운다.
	/// </summary>
	private static void FillBlock(string userId, Int64 tick, Span<byte> destination)
	{
		if (Volatile.Read(ref _seed) is null)
			throw new InvalidOperationException("AuditableRandom.Initialize()를 먼저 호출해야 합니다.");

		Span<byte> nonce = stackalloc byte[12];
		BinaryPrimitives.WriteInt64BigEndian(nonce[..8], tick);
		UInt32 counter = WriteUserIdHash(userId, nonce[8..]);

		BlockCore(_keyVecLow, _keyVecHigh, counter, nonce, destination);
	}

	/// <summary>
	/// 명시한 seed로 nonce를 구성해 destination(최소 64바이트)에 keystream을 채운다.
	/// </summary>
	private static void FillBlock(byte[] seed, string userId, Int64 tick, Span<byte> destination)
	{
		Span<byte> nonce = stackalloc byte[12];
		BinaryPrimitives.WriteInt64BigEndian(nonce[..8], tick);
		UInt32 counter = WriteUserIdHash(userId, nonce[8..]);

		ChaCha20Block(seed, nonce, counter, destination);
	}

	/// <summary>
	/// RFC 8439 ChaCha20 블록 함수. 주어진 (key 32바이트, nonce 12바이트, counter)로
	/// 64바이트 keystream 블록 하나를 destination 앞 64바이트에 little-endian으로 기록한다.
	/// 리틀엔디안 환경 가정(키/논스/출력을 LE로 적재·기록).
	/// </summary>
	internal static void ChaCha20Block(ReadOnlySpan<byte> key, ReadOnlySpan<byte> nonce, UInt32 counter,
		Span<byte> destination)
	{
		Vector128<UInt32> keyLow = Vector128.Create<byte>(key.Slice(0, 16)).AsUInt32();
		Vector128<UInt32> keyHigh = Vector128.Create<byte>(key.Slice(16, 16)).AsUInt32();
		BlockCore(keyLow, keyHigh, counter, nonce, destination);
	}

	/// <summary>
	/// ChaCha20 블록 함수의 SIMD 본체. 상태 4행을 Vector128 4개(a,b,c,d)로 두고
	/// 컬럼/대각 라운드를 4-lane 병렬로 수행한다. 대각 라운드는 b,c,d의 lane을 회전(diagonalize)해
	/// 컬럼 연산을 재사용한 뒤 되돌린다.
	/// </summary>
	private static void BlockCore(Vector128<UInt32> keyLow, Vector128<UInt32> keyHigh, UInt32 counter,
		ReadOnlySpan<byte> nonce, Span<byte> destination)
	{
		// lane 회전용 셔플 인덱스. result[i] = v[idx[i]].
		Vector128<UInt32> shuf1 = Vector128.Create(1u, 2u, 3u, 0u); // 왼쪽 1칸
		Vector128<UInt32> shuf2 = Vector128.Create(2u, 3u, 0u, 1u); // 2칸(자기역원)
		Vector128<UInt32> shuf3 = Vector128.Create(3u, 0u, 1u, 2u); // 3칸(= 1칸의 역)

		// 32비트 워드의 회전 16/8을 바이트 셔플 1연산으로 수행한다(x86 PSHUFB, ARM TBL).
		// LE lane 바이트 [b0,b1,b2,b3] 기준 ROL16→[b2,b3,b0,b1], ROL8→[b3,b0,b1,b2].
		Vector128<byte> rot16 = Vector128.Create((byte)2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13);
		Vector128<byte> rot8 = Vector128.Create((byte)3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14);

		Vector128<UInt32> a0 = Vector128.Create(0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u);
		Vector128<UInt32> b0 = keyLow;
		Vector128<UInt32> c0 = keyHigh;
		Vector128<UInt32> d0 = Vector128.Create(
			counter,
			BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(0, 4)),
			BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(4, 4)),
			BinaryPrimitives.ReadUInt32LittleEndian(nonce.Slice(8, 4)));

		Vector128<UInt32> a = a0, b = b0, c = c0, d = d0;

		for (Int32 i = 0; i < 10; i++)
		{
			// 컬럼 라운드
			a += b; d = RotateLeftBytes(d ^ a, rot16);
			c += d; b = RotateLeft(b ^ c, 12);
			a += b; d = RotateLeftBytes(d ^ a, rot8);
			c += d; b = RotateLeft(b ^ c, 7);

			// 대각화
			b = Vector128.Shuffle(b, shuf1);
			c = Vector128.Shuffle(c, shuf2);
			d = Vector128.Shuffle(d, shuf3);

			// 대각 라운드(컬럼 연산 재사용)
			a += b; d = RotateLeftBytes(d ^ a, rot16);
			c += d; b = RotateLeft(b ^ c, 12);
			a += b; d = RotateLeftBytes(d ^ a, rot8);
			c += d; b = RotateLeft(b ^ c, 7);

			// 대각화 되돌리기
			b = Vector128.Shuffle(b, shuf3);
			c = Vector128.Shuffle(c, shuf2);
			d = Vector128.Shuffle(d, shuf1);
		}

		a += a0; b += b0; c += c0; d += d0;

		a.AsByte().CopyTo(destination[..16]);
		b.AsByte().CopyTo(destination.Slice(16, 16));
		c.AsByte().CopyTo(destination.Slice(32, 16));
		d.AsByte().CopyTo(destination.Slice(48, 16));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<UInt32> RotateLeft(Vector128<UInt32> v, Int32 n) =>
		Vector128.ShiftLeft(v, n) | Vector128.ShiftRightLogical(v, 32 - n);

	/// <summary>회전량이 8의 배수(16/8)일 때 shift-or 대신 바이트 셔플 1연산으로 회전한다.</summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<UInt32> RotateLeftBytes(Vector128<UInt32> v, Vector128<byte> mask) =>
		Vector128.Shuffle(v.AsByte(), mask).AsUInt32();

	/// <summary>
	/// xxHash3(userId)의 64비트로 userId를 키스트림에 바인딩한다.
	/// 상위 32비트는 nonce 하위에 쓰고, 하위 32비트는 counter로 반환한다.
	/// 보안은 비밀 seed에 의존하므로 여기서는 암호 해시가 필요 없다(분포만 양호하면 충분).
	/// 성능을 위해 UTF-8 인코딩 없이 문자열의 UTF-16 바이트를 그대로 해싱한다.
	/// (출력이 리틀엔디안 환경에 묶이지만 .NET 실행 환경은 사실상 모두 LE다.)
	/// 빈 userId는 사전 계산값을 재사용한다.
	/// </summary>
	private static UInt32 WriteUserIdHash(string userId, Span<byte> nonceTail)
	{
		ArgumentNullException.ThrowIfNull(userId);
		UInt64 hash = userId.Length == 0
			? _emptyUserIdHash
			: XxHash3.HashToUInt64(MemoryMarshal.AsBytes(userId.AsSpan()));

		BinaryPrimitives.WriteUInt32BigEndian(nonceTail, (UInt32)(hash >> 32));
		return (UInt32)hash;
	}

	private static Int64 GetUniqueExecutionTicks()
	{
		Int64 captured, next;
		do
		{
			captured = Interlocked.Read(ref _lastTick);
			// 경과 타임스탬프를 100ns 단위로 환산해 _tickBase(UtcNow.Ticks, 100ns 단위)에 더한다.
			Int64 elapsed100ns = (Int64)((Stopwatch.GetTimestamp() - _startTimestamp) * _tickScale);
			next = Math.Max(_tickBase + elapsed100ns, captured + 1);
		}
		while (Interlocked.CompareExchange(ref _lastTick, next, captured) != captured);

		return next;
	}

	/// <summary>location 값을 value 미만일 때만 value로 끌어올린다(원자적).</summary>
	private static void InterlockedMax(ref Int64 location, Int64 value)
	{
		Int64 captured;
		do
		{
			captured = Interlocked.Read(ref location);
			if (captured >= value)
				return;
		}
		while (Interlocked.CompareExchange(ref location, value, captured) != captured);
	}
}
