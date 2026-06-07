using BenchmarkDotNet.Running;
using Benchmarks;

BenchmarkRunner.Run<AuditableRandomBenchmarks>(args: args);
