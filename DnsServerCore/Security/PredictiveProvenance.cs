// Copyright (c) 2026 Tekmyster Industries, LLC.
// Licensed under GPL-3.0-or-later.
using System;
using System.Linq;

namespace DnsServerCore.Security
{
    public sealed record InfrastructureAssociation(string Kind, string Value);
    public sealed record IndicatorProvenance(string SourceRecordId, string Revision, DateTime ObservedAt, DateTime FetchedAt, DateTime ValidFrom, DateTime ValidUntil, bool Retracted, DateTime? RegistrationCreatedAt, InfrastructureAssociation[] Associations);
    public sealed record ProvenanceView(string SourceRecordId, string Revision, DateTime? ObservedAt, DateTime? FetchedAt, DateTime? ValidUntil, string CurrentStatus, string AsOfStatus, DateTime? AssertedRegistrationCreatedAt, double? AssertedRegistrationAgeDays, InfrastructureAssociation[] Associations, string Basis);
    public static class PredictiveProvenance
    {
        public static void Validate(IndicatorProvenance p)
        {
            if (p is null) return;
            bool Text(string s) => !string.IsNullOrWhiteSpace(s) && s.Length <= 255;
            if (!Text(p.SourceRecordId) || !Text(p.Revision) || p.ObservedAt.Kind != DateTimeKind.Utc || p.FetchedAt.Kind != DateTimeKind.Utc || p.ValidFrom.Kind != DateTimeKind.Utc || p.ValidUntil.Kind != DateTimeKind.Utc || p.ValidUntil <= p.ValidFrom || p.RegistrationCreatedAt is { Kind: not DateTimeKind.Utc } || p.Associations is null || p.Associations.Length > 32 || p.Associations.Any(a => a is null || (a.Kind != "IP" && a.Kind != "ASN" && a.Kind != "CNAME" && a.Kind != "Hosting") || !Text(a.Value))) throw new ArgumentException("Context requires bounded source/revision, UTC observation/fetch/validity times and at most 32 typed infrastructure assertions.");
        }
        public static ProvenanceView View(IndicatorProvenance p, DateTime asOf, DateTime now)
        {
            const string basis = "Operator-supplied source assertion; no provider verification, ownership or maliciousness inference. Context is not a model feature.";
            if (p is null) return new(null, null, null, null, null, "Unknown", "Unknown", null, null, [], basis);
            try { Validate(p); } catch (ArgumentException) { return new(p.SourceRecordId, p.Revision, null, null, null, "Malformed; excluded", "Unavailable", null, null, [], basis); }
            string State(DateTime time) => p.ObservedAt > time || p.FetchedAt > time || p.ValidFrom > time ? "Future or not yet available; excluded" : p.Retracted ? "Retracted; excluded" : p.ValidUntil <= time ? "Expired; excluded" : "Within asserted validity; unverified";
            string current = State(now), historical = State(asOf);
            bool usable = historical.StartsWith("Within", StringComparison.Ordinal);
            DateTime? creation = usable && p.RegistrationCreatedAt <= asOf && p.RegistrationCreatedAt <= p.ObservedAt ? p.RegistrationCreatedAt : null;
            return new(p.SourceRecordId, p.Revision, p.ObservedAt, p.FetchedAt, p.ValidUntil, current, historical, creation, creation is null ? null : (asOf - creation.Value).TotalDays, usable ? p.Associations.ToArray() : [], basis);
        }
    }
}
