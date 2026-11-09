"""Preview or apply Windows 4625 source-IP enrichment without changing ingestion."""
import argparse

from app.services.windows_src_ip_service import enrich_stored_windows_4625_ips


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--after-event-id", default=None)
    parser.add_argument(
        "--apply", action="store_true",
        help="Write valid missing source IPs (default: dry run)",
    )
    args = parser.parse_args()

    report = enrich_stored_windows_4625_ips(
        limit=args.limit,
        after_event_id=args.after_event_id,
        apply=args.apply,
    )
    print(
        f"mode={'APPLY' if args.apply else 'DRY RUN'} "
        f"examined={report.examined} "
        f"valid_ips={report.valid_ips} updated={report.updated}"
    )
    print(f"next_after_event_id={report.next_after_event_id or 'NONE'}")


if __name__ == "__main__":
    main()
