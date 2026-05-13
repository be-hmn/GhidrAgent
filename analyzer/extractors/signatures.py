def extract_signature(
        func,
) -> dict:

    parameters = []
    return_type = "unknown"

    try:
        sig = func.getSignature()

        return_type = str(
            sig.getReturnType()
        )

        for param in sig.getParameters():

            parameters.append(
                str(param.getDataType())
            )

    except Exception:
        pass

    return {
        "parameters": parameters,
        "return_type": return_type,
    }