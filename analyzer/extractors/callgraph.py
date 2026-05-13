def extract_callgraph(
        flat_api,
        func,
) -> dict:

    calls = []
    called_by = []

    try:
        for f in func.getCalledFunctions(
                flat_api.monitor
        ):
            calls.append(f.getName())

    except Exception:
        pass

    try:
        for f in func.getCallingFunctions(
                flat_api.monitor
        ):
            called_by.append(f.getName())

    except Exception:
        pass

    return {
        "calls": sorted(set(calls)),
        "called_by": sorted(set(called_by)),
    }