def extract_api_calls(
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
                    if ref.isExternalReference():

                        symbol = (
                            program
                            .getSymbolTable()
                            .getPrimarySymbol(
                                ref.getToAddress()
                            )
                        )

                        if symbol:
                            results.append(
                                symbol.getName()
                            )
                        else:
                            results.append(
                                str(ref.getToAddress())
                            )

                except Exception:
                    continue

    except Exception:
        pass

    return sorted(set(results))