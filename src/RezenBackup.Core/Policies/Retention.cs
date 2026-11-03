using System.Globalization;

namespace RezenBackup.Core.Policies;

public enum RetentionKind
{
    Forever = 0,
    LastCount = 1,
    Age = 2,
    Smart = 3,
}

/// <summary>Retention policy (spec §59).</summary>
public sealed record RetentionPolicy
{
    public RetentionKind Kind { get; init; } = RetentionKind.Smart;

    /// <summary>For <see cref="RetentionKind.LastCount"/>: 1 (mirror-like), 5, 10, 30…</summary>
    public int Count { get; init; } = 30;

    /// <summary>For <see cref="RetentionKind.Age"/>.</summary>
    public int AgeDays { get; init; } = 30;

    public int SmartDailyDays { get; init; } = 7;

    public int SmartWeeklyWeeks { get; init; } = 13;

    public int SmartMonthlyMonths { get; init; } = 12;

    /// <summary>Always keep at least this many most-recent verified snapshots, whatever their age (DESIGN §20.2).</summary>
    public int MinimumKeep { get; init; } = 3;

    public static RetentionPolicy Forever => new() { Kind = RetentionKind.Forever };

    public static RetentionPolicy Smart => new() { Kind = RetentionKind.Smart };

    public static RetentionPolicy LastN(int n) => new() { Kind = RetentionKind.LastCount, Count = n, MinimumKeep = Math.Min(3, n) };

    public static RetentionPolicy Days(int days) => new() { Kind = RetentionKind.Age, AgeDays = days };

    public bool IsMirrorLike => Kind == RetentionKind.LastCount && Count <= 1;

    public string Describe() => Kind switch
    {
        RetentionKind.Forever => "Forever",
        RetentionKind.LastCount when Count <= 1 => "Latest snapshot only (mirror-like)",
        RetentionKind.LastCount => $"Last {Count} snapshots",
        RetentionKind.Age when AgeDays % 365 == 0 => AgeDays == 365 ? "1 year" : $"{AgeDays / 365} years",
        RetentionKind.Age when AgeDays is 180 or 182 or 183 => "6 months",
        RetentionKind.Age => $"{AgeDays} days",
        RetentionKind.Smart => $"Smart: daily for {SmartDailyDays} days, weekly for {SmartWeeklyWeeks / 4.33:0} months, monthly for {SmartMonthlyMonths} months",
        _ => Kind.ToString(),
    };
}

public sealed record RetentionCandidate(Guid SnapshotId, DateTimeOffset Time, bool Pinned, bool Verified);

public static class RetentionCalculator
{
    /// <summary>
    /// Returns snapshots the policy allows deleting. Safety rules: the newest verified snapshot, the
    /// <see cref="RetentionPolicy.MinimumKeep"/> most recent verified snapshots, pinned snapshots and unverified
    /// snapshots are never selected (DESIGN §20.2).
    /// </summary>
    public static IReadOnlyList<Guid> SelectForDeletion(IReadOnlyList<RetentionCandidate> snapshots, RetentionPolicy policy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(snapshots);
        ArgumentNullException.ThrowIfNull(policy);
        if (policy.Kind == RetentionKind.Forever)
        {
            return [];
        }

        var verified = snapshots.Where(s => s.Verified).OrderByDescending(s => s.Time).ToList();
        if (verified.Count == 0)
        {
            return [];
        }

        int minimumKeep = Math.Max(1, policy.Kind == RetentionKind.LastCount ? Math.Max(1, Math.Min(policy.MinimumKeep, policy.Count)) : policy.MinimumKeep);
        var keep = new HashSet<Guid>(verified.Take(minimumKeep).Select(s => s.SnapshotId));
        foreach (var s in verified.Where(s => s.Pinned))
        {
            keep.Add(s.SnapshotId);
        }

        switch (policy.Kind)
        {
            case RetentionKind.LastCount:
                foreach (var s in verified.Take(Math.Max(1, policy.Count)))
                {
                    keep.Add(s.SnapshotId);
                }

                break;

            case RetentionKind.Age:
                foreach (var s in verified.Where(s => now - s.Time <= TimeSpan.FromDays(policy.AgeDays)))
                {
                    keep.Add(s.SnapshotId);
                }

                break;

            case RetentionKind.Smart:
                ApplySmart(verified, policy, now, keep);
                break;
        }

        return verified.Where(s => !keep.Contains(s.SnapshotId)).Select(s => s.SnapshotId).ToList();
    }

    private static void ApplySmart(List<RetentionCandidate> newestFirst, RetentionPolicy policy, DateTimeOffset now, HashSet<Guid> keep)
    {
        var seenWeeks = new HashSet<string>();
        var seenMonths = new HashSet<string>();
        foreach (var s in newestFirst)
        {
            var age = now - s.Time;
            if (age <= TimeSpan.FromDays(policy.SmartDailyDays))
            {
                keep.Add(s.SnapshotId);
                continue;
            }

            var local = s.Time.ToLocalTime();
            if (age <= TimeSpan.FromDays(policy.SmartWeeklyWeeks * 7))
            {
                var week = ISOWeek.GetYear(local.DateTime).ToString(CultureInfo.InvariantCulture) + "-" + ISOWeek.GetWeekOfYear(local.DateTime).ToString(CultureInfo.InvariantCulture);
                if (seenWeeks.Add(week))
                {
                    keep.Add(s.SnapshotId);
                }

                continue;
            }

            if (age <= TimeSpan.FromDays(policy.SmartMonthlyMonths * 30.44))
            {
                var month = local.ToString("yyyy-MM", CultureInfo.InvariantCulture);
                if (seenMonths.Add(month))
                {
                    keep.Add(s.SnapshotId);
                }
            }
        }
    }
}
