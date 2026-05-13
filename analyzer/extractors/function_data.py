from analyzer.extractors.callgraph import (
    extract_callgraph,
)

from analyzer.extractors.xrefs import (
    extract_xrefs,
)

from analyzer.extractors.api_calls import (
    extract_api_calls,
)

from analyzer.extractors.strings import (
    extract_strings,
)

from analyzer.extractors.signatures import (
    extract_signature,
)


def extract_function_data(
        flat_api,
        func,
) -> dict:

    callgraph = extract_callgraph(
        flat_api,
        func,
    )

    xrefs = extract_xrefs(
        flat_api,
        func,
    )

    signature = extract_signature(
        func,
    )

    return {
        "name": func.getName(),

        "entry": str(
            func.getEntryPoint()
        ),

        "body_size": (
            func.getBody()
            .getNumAddresses()
        ),

        "calls": callgraph["calls"],

        "called_by": (
            callgraph["called_by"]
        ),

        "xrefs_in": (
            xrefs["xrefs_in"]
        ),

        "xrefs_out": (
            xrefs["xrefs_out"]
        ),

        "api_calls": extract_api_calls(
            flat_api,
            func,
        ),

        "strings": extract_strings(
            flat_api,
            func,
        ),

        "parameters": (
            signature["parameters"]
        ),

        "return_type": (
            signature["return_type"]
        ),
    }