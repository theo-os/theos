def _copy_files_impl(ctx: AnalysisContext) -> list[Provider]:
    srcs = {
        name: src
        for name, src in ctx.attrs.srcs.items()
    }

    outdir = ctx.actions.declare_output(ctx.label.name, dir = True)
    outdir = ctx.actions.copied_dir(
        outdir,
        srcs,
    )

    return [
        DefaultInfo(
            default_output = outdir,
            sub_targets = {
                name: [ DefaultInfo(default_output = outdir.project(name)) ]
                for name in ctx.attrs.srcs.keys()
            }
        ),
    ]

copy_files = rule(
    impl = _copy_files_impl,
    attrs = {
        "srcs": attrs.dict(attrs.string(), attrs.source()),
    }
)
