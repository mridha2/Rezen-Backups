namespace RezenBackup.Core.Policies;

public enum ScheduleKind
{
    Manual = 0,
    Daily = 1,
    Weekly = 2,
    Monthly = 3,
    Interval = 4,
}

/// <summary>
/// A backup schedule (spec §44). Weekly with several days covers "Selected Days".
/// </summary>
public sealed record Schedule
{
    public ScheduleKind Kind { get; init; } = ScheduleKind.Daily;

    public TimeOnly TimeOfDay { get; init; } = new(20, 0);

    public IReadOnlyList<DayOfWeek> Days { get; init; } = [];

    /// <summary>1..31; clamped to the last day of shorter months.</summary>
    public int DayOfMonth { get; init; } = 1;

    /// <summary>Hours between runs for <see cref="ScheduleKind.Interval"/>: 1, 2, 6 or 12.</summary>
    public int IntervalHours { get; init; } = 6;

    public static Schedule Manual => new() { Kind = ScheduleKind.Manual };

    public static Schedule DailyAt(int hour, int minute = 0) => new() { Kind = ScheduleKind.Daily, TimeOfDay = new TimeOnly(hour, minute) };

    public string Describe() => Kind switch
    {
        ScheduleKind.Manual => "Manual only",
        ScheduleKind.Daily => $"Daily at {Format(TimeOfDay)}",
        ScheduleKind.Weekly when Days.Count == 1 => $"Weekly on {Days[0]} at {Format(TimeOfDay)}",
        ScheduleKind.Weekly => $"{string.Join(", ", Days.Select(d => d.ToString()[..3]))} at {Format(TimeOfDay)}",
        ScheduleKind.Monthly => $"Monthly on day {DayOfMonth} at {Format(TimeOfDay)}",
        ScheduleKind.Interval => IntervalHours == 1 ? "Every hour" : $"Every {IntervalHours} hours",
        _ => Kind.ToString(),
    };

    private static string Format(TimeOnly t) => t.ToString("h:mm tt", System.Globalization.CultureInfo.InvariantCulture);
}

public static class ScheduleCalculator
{
    /// <summary>
    /// Next occurrence strictly after <paramref name="after"/>, computed in local wall-clock time so DST changes keep
    /// "8:00 PM" at 8:00 PM. Returns null for manual schedules.
    /// </summary>
    public static DateTimeOffset? NextRun(Schedule schedule, DateTimeOffset after, TimeZoneInfo? zone = null)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        zone ??= TimeZoneInfo.Local;
        var local = TimeZoneInfo.ConvertTime(after, zone).DateTime;

        switch (schedule.Kind)
        {
            case ScheduleKind.Manual:
                return null;

            case ScheduleKind.Interval:
                {
                    int hours = Math.Clamp(schedule.IntervalHours, 1, 24);
                    // Align to hour boundaries from local midnight so runs land on predictable times.
                    var dayStart = local.Date;
                    var candidate = dayStart;
                    while (candidate <= local)
                    {
                        candidate = candidate.AddHours(hours);
                    }

                    return ToOffset(candidate, zone);
                }

            case ScheduleKind.Daily:
                {
                    var candidate = local.Date + schedule.TimeOfDay.ToTimeSpan();
                    if (candidate <= local)
                    {
                        candidate = candidate.AddDays(1);
                    }

                    return ToOffset(candidate, zone);
                }

            case ScheduleKind.Weekly:
                {
                    var days = schedule.Days.Count == 0 ? [DayOfWeek.Monday] : schedule.Days;
                    for (int i = 0; i <= 7; i++)
                    {
                        var date = local.Date.AddDays(i);
                        if (!days.Contains(date.DayOfWeek))
                        {
                            continue;
                        }

                        var candidate = date + schedule.TimeOfDay.ToTimeSpan();
                        if (candidate > local)
                        {
                            return ToOffset(candidate, zone);
                        }
                    }

                    return null;
                }

            case ScheduleKind.Monthly:
                {
                    for (int i = 0; i <= 2; i++)
                    {
                        var month = new DateTime(local.Year, local.Month, 1).AddMonths(i);
                        int day = Math.Min(Math.Max(1, schedule.DayOfMonth), DateTime.DaysInMonth(month.Year, month.Month));
                        var candidate = new DateTime(month.Year, month.Month, day) + schedule.TimeOfDay.ToTimeSpan();
                        if (candidate > local)
                        {
                            return ToOffset(candidate, zone);
                        }
                    }

                    return null;
                }

            default:
                return null;
        }
    }

    /// <summary>
    /// True if at least one scheduled occurrence fell between the last attempt and now (a missed or due run).
    /// </summary>
    public static bool IsDue(Schedule schedule, DateTimeOffset? lastAttempt, DateTimeOffset now, DateTimeOffset jobCreated, TimeZoneInfo? zone = null)
    {
        var reference = lastAttempt ?? jobCreated;
        var next = NextRun(schedule, reference, zone);
        return next is { } n && n <= now;
    }

    private static DateTimeOffset ToOffset(DateTime localWallClock, TimeZoneInfo zone)
    {
        // Skip non-existent times (spring-forward gap) by moving forward to the first valid instant.
        var unspecified = DateTime.SpecifyKind(localWallClock, DateTimeKind.Unspecified);
        while (zone.IsInvalidTime(unspecified))
        {
            unspecified = unspecified.AddMinutes(15);
        }

        var offset = zone.GetUtcOffset(unspecified);
        return new DateTimeOffset(unspecified, offset);
    }
}
