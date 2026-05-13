def extract_xrefs(
        flat_api,
        func,
) -> dict:

    ref_mgr = (
        flat_api
        .getCurrentProgram()
        .getReferenceManager()
    )

    xrefs_in = 0
    xrefs_out = 0

    try:
        for addr in func.getBody():

            xrefs_in += len(
                list(
                    ref_mgr.getReferencesTo(addr)
                )
            )

            xrefs_out += len(
                list(
                    ref_mgr.getReferencesFrom(addr)
                )
            )

    except Exception:
        pass

    return {
        "xrefs_in": xrefs_in,
        "xrefs_out": xrefs_out,
    }