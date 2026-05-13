def extract_strings(
        flat_api,
        func,
):

    program = flat_api.getCurrentProgram()

    listing = program.getListing()

    ref_mgr = program.getReferenceManager()

    results = []

    try:
        instructions = listing.getInstructions(
            func.getBody(),
            True,
        )

        while instructions.hasNext():

            instruction = instructions.next()

            refs = ref_mgr.getReferencesFrom(
                instruction.getAddress()
            )

            for ref in refs:

                try:
                    data = listing.getDefinedDataAt(
                        ref.getToAddress()
                    )

                    if not data:
                        continue

                    value = data.getValue()

                    if value is None:
                        continue

                    value_str = str(value)

                    if (
                            len(value_str) > 0
                            and len(value_str) < 256
                    ):
                        results.append(
                            value_str
                        )

                except Exception:
                    continue

    except Exception:
        pass

    return sorted(set(results))