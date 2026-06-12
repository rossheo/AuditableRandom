using System.Reflection;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Columns;
using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Exporters;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Loggers;
using BenchmarkDotNet.Toolchains.InProcess.Emit;
using RandomLib;

namespace Benchmarks;

[Config(typeof(InProcessConfig))]
[MemoryDiagnoser]
public class AuditableRandomBenchmarks
{
    private sealed class InProcessConfig : ManualConfig
    {
        public InProcessConfig()
        {
            AddJob(Job.MediumRun.WithToolchain(InProcessEmitToolchain.Instance));
            AddColumnProvider(DefaultColumnProviders.Instance);
            AddLogger(ConsoleLogger.Default);
            AddExporter(MarkdownExporter.Default);
        }
    }

    private static int _initialized;

    // private static 메서드라 리플렉션으로 델리게이트를 만들어 직접 호출한다.
    private static readonly Func<long> _getUniqueExecutionTicks = CreateGetUniqueExecutionTicksDelegate();

    private static Func<long> CreateGetUniqueExecutionTicksDelegate()
    {
        MethodInfo method = typeof(AuditableRandom).GetMethod("GetUniqueExecutionTicks", BindingFlags.NonPublic | BindingFlags.Static)
            ?? throw new MissingMethodException(nameof(AuditableRandom), "GetUniqueExecutionTicks");
        return (Func<long>)method.CreateDelegate(typeof(Func<long>));
    }

    private readonly List<int> _list100 = Enumerable.Range(0, 100).ToList();

    [GlobalSetup]
    public void Setup()
    {
        if (Interlocked.CompareExchange(ref _initialized, 1, 0) == 0)
        {
            byte[] seed = new byte[32];
            RandomNumberGenerator.Fill(seed);
            AuditableRandom.Initialize(seed);
        }
    }

    // ── 기준선 ────────────────────────────────────────────────────────────────

    [Benchmark(Baseline = true)]
    public int SystemRandom_Next() => Random.Shared.Next(1_000_000);

    [Benchmark]
    public int RandomNumberGenerator_GetInt32() => RandomNumberGenerator.GetInt32(1_000_000);

    // ── AuditableRandom: 빈 userId (캐시된 해시 경로) ─────────────────────────

    [Benchmark]
    public int Next_EmptyUserId() => AuditableRandom.Next(1_000_000);

    [Benchmark]
    public long NextInt64_EmptyUserId() => AuditableRandom.NextInt64(1_000_000_000_000L);

    [Benchmark]
    public double NextDouble_EmptyUserId() => AuditableRandom.NextDouble();

    [Benchmark]
    public float NextSingle_EmptyUserId() => AuditableRandom.NextSingle();

    // ── AuditableRandom: 비어 있지 않은 userId (xxHash3 경로) ─────────────────

    [Benchmark]
    public int Next_WithUserId() => AuditableRandom.Next("user-0000000000000001", 1_000_000);

    [Benchmark]
    public long NextInt64_WithUserId() => AuditableRandom.NextInt64("user-0000000000000001", 1_000_000_000_000L);

    [Benchmark]
    public double NextDouble_WithUserId() => AuditableRandom.NextDouble("user-0000000000000001");

    // ── 원시 블록 생성 ────────────────────────────────────────────────────────

    [Benchmark]
    public byte[] GetBlock_EmptyUserId() => AuditableRandom.GetBlockChaCha20(string.Empty, out _);

    [Benchmark]
    public byte[] GetBlock_WithUserId() => AuditableRandom.GetBlockChaCha20("user-0000000000000001", out _);

    // ── 내부 타임스탬프(틱) 생성 ─────────────────────────────────────────────

    [Benchmark]
    public long GetUniqueExecutionTicks() => _getUniqueExecutionTicks();

    // ── 셔플 ─────────────────────────────────────────────────────────────────

    // List<T>는 IList 오버로드로 들어가도 내부에서 CollectionsMarshal.AsSpan 빠른 경로를 탄다.
    [Benchmark]
    public void Shuffle100() => AuditableRandom.Shuffle(_list100);
}
