from log_parser import load_logs

def main():
    logs = load_logs("data/logs.json")

    print("\n===== ECS SAMPLE =====\n")
    print(logs[0]["ecs"])

    print("\n===== SOC ENRICHMENT SAMPLE =====\n")
    print(logs[0]["soc_enrichment"])

    print("\nTOTAL LOGS:", len(logs))


if __name__ == "__main__":
    main()