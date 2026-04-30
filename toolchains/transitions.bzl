def _platform_transition_impl(settings, attr):
    return {"//command_line_option:platforms": [str(attr.platform)]}

_platform_transition = transition(
    implementation = _platform_transition_impl,
    inputs = [],
    outputs = ["//command_line_option:platforms"],
)

def _transitioned_dependency_impl(ctx):
    return [
        DefaultInfo(
            files = ctx.attr.src[DefaultInfo].files,
            runfiles = ctx.attr.src[DefaultInfo].default_runfiles,
        ),
    ]

transitioned_dependency = rule(
    implementation = _transitioned_dependency_impl,
    attrs = {
        "src": attr.label(cfg = _platform_transition),
        "platform": attr.label(mandatory = True),
        "_allowlist_function_transition": attr.label(
            default = "@bazel_tools//tools/allowlists/function_transition_allowlist",
        ),
    },
)
