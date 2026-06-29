from agent import (
    args,
    generate_and_iterate_tests,
    generate_privacy_probes,
    generate_scenarios,
    run_manual_test,
)

# from agent.verify_functional_tests import verify_tests

if __name__ == "__main__":
    if args.generate_scenarios:
        generate_scenarios()
    elif args.generate_tests:
        generate_and_iterate_tests()
        # verify_tests()
    elif args.manual_test:
        run_manual_test(args)
    else:
        generate_privacy_probes()
