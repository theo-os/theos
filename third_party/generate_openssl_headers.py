#!/usr/bin/env python3
from __future__ import annotations

import pathlib
import re


ROOT = pathlib.Path(__file__).resolve().parent / "openssl"
GEN_ROOT = ROOT / "generated" / "include"


VERSION = {
    "major": "4",
    "minor": "1",
    "patch": "0",
    "prerelease": "-dev",
    "build_metadata": "",
    "release_date": "",
    "shlib_version": "4",
}


PARAMNAMES = ROOT / "util" / "perl" / "OpenSSL" / "paramnames.pm"
PROVIDER_HEADER_SPECS = {
    "providers/common/include/prov/der_digests.h.in": [
        "providers/common/der/NIST.asn1",
        "providers/common/der/DIGESTS.asn1",
    ],
    "providers/common/include/prov/der_dsa.h.in": [
        "providers/common/der/DSA.asn1",
    ],
    "providers/common/include/prov/der_ec.h.in": [
        "providers/common/der/EC.asn1",
    ],
    "providers/common/include/prov/der_ecx.h.in": [
        "providers/common/der/ECX.asn1",
    ],
    "providers/common/include/prov/der_hkdf.h.in": [
        "providers/common/der/HKDF.asn1",
    ],
    "providers/common/include/prov/der_ml_dsa.h.in": [
        "providers/common/der/ML_DSA.asn1",
    ],
    "providers/common/include/prov/der_rsa.h.in": [
        "providers/common/der/NIST.asn1",
        "providers/common/der/RSA.asn1",
    ],
    "providers/common/include/prov/der_slh_dsa.h.in": [
        "providers/common/der/SLH_DSA.asn1",
    ],
    "providers/common/include/prov/der_sm2.h.in": [
        "providers/common/der/SM2.asn1",
    ],
    "providers/common/include/prov/der_wrap.h.in": [
        "providers/common/der/wrap.asn1",
    ],
}
OID_DEF_RE = re.compile(
    r"(?P<name>[a-z](?:[-_A-Za-z0-9]*[A-Za-z0-9])?)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{(?P<value>.*?)\}",
    re.S,
)
OID_TOKEN_RE = re.compile(
    r"(?:[A-Za-z][-_A-Za-z0-9]*[A-Za-z0-9]?\s*\(\d+\)|\d+|[A-Za-z][-_A-Za-z0-9]*[A-Za-z0-9]?)"
)
PARAM_DECODER_RE = re.compile(
    r"produce_param_decoder(?P<with_count>_with_count)?\s*\(\s*'\s*(?P<name>[^']+)\s*'\s*,\s*\((?P<body>.*)\)\s*;",
    re.S,
)
PARAM_ENTRY_RE = re.compile(
    r"\[\s*'(?P<key>[^']+)'\s*,\s*'(?P<field>[^']+)'\s*,\s*'(?P<type>[^']+)'(?:\s*,\s*'(?P<mode>[^']+)')?\s*\]",
)


def stack_macros_int(nametype: str, realtype: str, plaintype: str) -> str:
    return f"""SKM_DEFINE_STACK_OF_INTERNAL({nametype}, {realtype}, {plaintype})
#define sk_{nametype}_num(sk) OPENSSL_sk_num(ossl_check_const_{nametype}_sk_type(sk))
#define sk_{nametype}_value(sk, idx) (({realtype} *)OPENSSL_sk_value(ossl_check_const_{nametype}_sk_type(sk), (idx)))
#define sk_{nametype}_new(cmp) ((STACK_OF({nametype}) *)OPENSSL_sk_set_cmp_thunks(OPENSSL_sk_new(ossl_check_{nametype}_compfunc_type(cmp)), sk_{nametype}_cmpfunc_thunk))
#define sk_{nametype}_new_null() ((STACK_OF({nametype}) *)OPENSSL_sk_set_thunks(OPENSSL_sk_new_null(), sk_{nametype}_freefunc_thunk))
#define sk_{nametype}_new_reserve(cmp, n) ((STACK_OF({nametype}) *)OPENSSL_sk_set_cmp_thunks(OPENSSL_sk_new_reserve(ossl_check_{nametype}_compfunc_type(cmp), (n)), sk_{nametype}_cmpfunc_thunk))
#define sk_{nametype}_reserve(sk, n) OPENSSL_sk_reserve(ossl_check_{nametype}_sk_type(sk), (n))
#define sk_{nametype}_free(sk) OPENSSL_sk_free(ossl_check_{nametype}_sk_type(sk))
#define sk_{nametype}_zero(sk) OPENSSL_sk_zero(ossl_check_{nametype}_sk_type(sk))
#define sk_{nametype}_delete(sk, i) (({realtype} *)OPENSSL_sk_delete(ossl_check_{nametype}_sk_type(sk), (i)))
#define sk_{nametype}_delete_ptr(sk, ptr) (({realtype} *)OPENSSL_sk_delete_ptr(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr)))
#define sk_{nametype}_push(sk, ptr) OPENSSL_sk_push(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr))
#define sk_{nametype}_unshift(sk, ptr) OPENSSL_sk_unshift(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr))
#define sk_{nametype}_pop(sk) (({realtype} *)OPENSSL_sk_pop(ossl_check_{nametype}_sk_type(sk)))
#define sk_{nametype}_shift(sk) (({realtype} *)OPENSSL_sk_shift(ossl_check_{nametype}_sk_type(sk)))
#define sk_{nametype}_pop_free(sk, freefunc) OPENSSL_sk_pop_free(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_freefunc_type(freefunc))
#define sk_{nametype}_insert(sk, ptr, idx) OPENSSL_sk_insert(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr), (idx))
#define sk_{nametype}_set(sk, idx, ptr) (({realtype} *)OPENSSL_sk_set(ossl_check_{nametype}_sk_type(sk), (idx), ossl_check_{nametype}_type(ptr)))
#define sk_{nametype}_find(sk, ptr) OPENSSL_sk_find(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr))
#define sk_{nametype}_find_ex(sk, ptr) OPENSSL_sk_find_ex(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr))
#define sk_{nametype}_find_all(sk, ptr, pnum) OPENSSL_sk_find_all(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_type(ptr), pnum)
#define sk_{nametype}_sort(sk) OPENSSL_sk_sort(ossl_check_{nametype}_sk_type(sk))
#define sk_{nametype}_is_sorted(sk) OPENSSL_sk_is_sorted(ossl_check_const_{nametype}_sk_type(sk))
#define sk_{nametype}_dup(sk) ((STACK_OF({nametype}) *)OPENSSL_sk_dup(ossl_check_const_{nametype}_sk_type(sk)))
#define sk_{nametype}_deep_copy(sk, copyfunc, freefunc) ((STACK_OF({nametype}) *)OPENSSL_sk_deep_copy(ossl_check_const_{nametype}_sk_type(sk), ossl_check_{nametype}_copyfunc_type(copyfunc), ossl_check_{nametype}_freefunc_type(freefunc)))
#define sk_{nametype}_set_cmp_func(sk, cmp) ((sk_{nametype}_compfunc)OPENSSL_sk_set_cmp_func(ossl_check_{nametype}_sk_type(sk), ossl_check_{nametype}_compfunc_type(cmp)))
"""


def generate_stack_macros(name: str) -> str:
    return stack_macros_int(name, name, name)


def generate_const_stack_macros(name: str) -> str:
    return stack_macros_int(name, f"const {name}", name)


def generate_stack_string_macros() -> str:
    return stack_macros_int("OPENSSL_STRING", "char", "char")


def generate_stack_const_string_macros() -> str:
    return stack_macros_int("OPENSSL_CSTRING", "const char", "char")


def generate_stack_block_macros() -> str:
    return stack_macros_int("OPENSSL_BLOCK", "void", "void")


def generate_lhash_macros(name: str) -> str:
    return f"""DEFINE_LHASH_OF_INTERNAL({name});
#define lh_{name}_new(hfn, cmp) ((LHASH_OF({name}) *)OPENSSL_LH_set_thunks(OPENSSL_LH_new(ossl_check_{name}_lh_hashfunc_type(hfn), ossl_check_{name}_lh_compfunc_type(cmp)), lh_{name}_hash_thunk, lh_{name}_comp_thunk, lh_{name}_doall_thunk, lh_{name}_doall_arg_thunk))
#define lh_{name}_free(lh) OPENSSL_LH_free(ossl_check_{name}_lh_type(lh))
#define lh_{name}_flush(lh) OPENSSL_LH_flush(ossl_check_{name}_lh_type(lh))
#define lh_{name}_insert(lh, ptr) (({name} *)OPENSSL_LH_insert(ossl_check_{name}_lh_type(lh), ossl_check_{name}_lh_plain_type(ptr)))
#define lh_{name}_delete(lh, ptr) (({name} *)OPENSSL_LH_delete(ossl_check_{name}_lh_type(lh), ossl_check_const_{name}_lh_plain_type(ptr)))
#define lh_{name}_retrieve(lh, ptr) (({name} *)OPENSSL_LH_retrieve(ossl_check_{name}_lh_type(lh), ossl_check_const_{name}_lh_plain_type(ptr)))
#define lh_{name}_error(lh) OPENSSL_LH_error(ossl_check_{name}_lh_type(lh))
#define lh_{name}_num_items(lh) OPENSSL_LH_num_items(ossl_check_{name}_lh_type(lh))
#define lh_{name}_node_stats_bio(lh, out) OPENSSL_LH_node_stats_bio(ossl_check_const_{name}_lh_type(lh), out)
#define lh_{name}_node_usage_stats_bio(lh, out) OPENSSL_LH_node_usage_stats_bio(ossl_check_const_{name}_lh_type(lh), out)
#define lh_{name}_stats_bio(lh, out) OPENSSL_LH_stats_bio(ossl_check_const_{name}_lh_type(lh), out)
#define lh_{name}_get_down_load(lh) OPENSSL_LH_get_down_load(ossl_check_{name}_lh_type(lh))
#define lh_{name}_set_down_load(lh, dl) OPENSSL_LH_set_down_load(ossl_check_{name}_lh_type(lh), dl)
#define lh_{name}_doall(lh, dfn) OPENSSL_LH_doall(ossl_check_{name}_lh_type(lh), ossl_check_{name}_lh_doallfunc_type(dfn))
"""


def render_expr(expr: str) -> str:
    expr = expr.strip()

    parts: list[str] = []

    for name in re.findall(r'generate_stack_macros\("([^"]+)"\)', expr):
        parts.append(generate_stack_macros(name))
    for name in re.findall(r'generate_const_stack_macros\("([^"]+)"\)', expr):
        parts.append(generate_const_stack_macros(name))
    for name in re.findall(r'generate_lhash_macros\("([^"]+)"\)', expr):
        parts.append(generate_lhash_macros(name))

    if "generate_stack_string_macros()" in expr:
        parts.append(generate_stack_string_macros())
    if "generate_stack_const_string_macros()" in expr:
        parts.append(generate_stack_const_string_macros())
    if "generate_stack_block_macros()" in expr:
        parts.append(generate_stack_block_macros())

    if parts:
        return "\n".join(parts)

    if expr == 'join("\n * ", @autowarntext)':
        return "generated from OpenSSL templates"
    if expr == 'join("\n",map { "/* $_ */" } @autowarntext)':
        return "/* generated from OpenSSL templates */"
    if expr == "$config{major}":
        return VERSION["major"]
    if expr == "$config{minor}":
        return VERSION["minor"]
    if expr == "$config{patch}":
        return VERSION["patch"]
    if expr == "$config{prerelease}":
        return VERSION["prerelease"]
    if expr == "$config{build_metadata}":
        return VERSION["build_metadata"]
    if expr == "$config{shlib_version}":
        return VERSION["shlib_version"]
    if expr == "$config{version}":
        return f"{VERSION['major']}.{VERSION['minor']}.{VERSION['patch']}{VERSION['prerelease']}"
    if expr == "$config{full_version}":
        return f"{VERSION['major']}.{VERSION['minor']}.{VERSION['patch']}{VERSION['prerelease']}"
    if expr == "$config{release_date}":
        return VERSION["release_date"]
    if expr == '"$config{full_version} $config{release_date}"':
        return f"{VERSION['major']}.{VERSION['minor']}.{VERSION['patch']}{VERSION['prerelease']}".strip()
    if expr == "platform->dsoext()":
        return ".dll"
    if expr.startswith('join(", ", map { "0x$_" } unpack("(A2)*", $config{FIPSKEY}))'):
        return "0x00"

    return ""


def replace_expr(match: re.Match[str]) -> str:
    return render_expr(match.group(1))


def render_template(text: str) -> str:
    text = render_param_decoder_template(text)
    text = re.sub(r"\{-(.*?)-\}", replace_expr, text, flags=re.S)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def generate_configuration_header() -> str:
    return """/* generated by third_party/generate_openssl_headers.py */
#ifndef OPENSSL_CONFIGURATION_H
#define OPENSSL_CONFIGURATION_H
#pragma once

#define OPENSSL_CONFIGURED_API 40100
#define OPENSSL_SYS_WIN32
#define OPENSSL_THREADS
#define OPENSSL_NO_POSIX_IO
#define OPENSSL_NO_COMP_ALG
#define OPENSSLDIR "C:\\OpenSSL"
#define MODULESDIR "C:\\OpenSSL\\providers"
#define SIXTY_FOUR_BIT
#define RC4_INT unsigned int

#endif /* OPENSSL_CONFIGURATION_H */
"""


def generate_buildinf_header() -> str:
    return """/* generated by third_party/generate_openssl_headers.py */
#ifndef OPENSSL_BUILDINF_H
#define OPENSSL_BUILDINF_H
#pragma once

#define DATE ""
#define PLATFORM "platform: windows"
#define compiler_flags ""

#define OPENSSLDIR "C:\\OpenSSL"
#define MODULESDIR "C:\\OpenSSL\\providers"

#endif /* OPENSSL_BUILDINF_H */
"""


def generate_opensslv_header() -> str:
    return f"""/* generated by third_party/generate_openssl_headers.py */
#ifndef OPENSSL_OPENSSLV_H
#define OPENSSL_OPENSSLV_H
#pragma once

#ifdef __cplusplus
extern "C" {{
#endif

#define OPENSSL_VERSION_MAJOR {VERSION["major"]}
#define OPENSSL_VERSION_MINOR {VERSION["minor"]}
#define OPENSSL_VERSION_PATCH {VERSION["patch"]}
#define OPENSSL_VERSION_PRE_RELEASE "{VERSION["prerelease"]}"
#define OPENSSL_VERSION_BUILD_METADATA "{VERSION["build_metadata"]}"
#define OPENSSL_SHLIB_VERSION {VERSION["shlib_version"]}
#define OPENSSL_VERSION_PREREQ(maj, min) \
    ((OPENSSL_VERSION_MAJOR << 16) + OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))
#define OPENSSL_VERSION_STR "{VERSION["major"]}.{VERSION["minor"]}.{VERSION["patch"]}{VERSION["prerelease"]}"
#define OPENSSL_FULL_VERSION_STR "{VERSION["major"]}.{VERSION["minor"]}.{VERSION["patch"]}{VERSION["prerelease"]}"
#define OPENSSL_RELEASE_DATE ""
#define OPENSSL_VERSION_TEXT "OpenSSL {VERSION["major"]}.{VERSION["minor"]}.{VERSION["patch"]}{VERSION["prerelease"]}"
#define OPENSSL_VERSION_NUMBER \
    ((OPENSSL_VERSION_MAJOR<<28) | (OPENSSL_VERSION_MINOR<<20) | (OPENSSL_VERSION_PATCH<<4) | 0x0L)

#ifdef __cplusplus
}}
#endif

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_OPENSSLV_H
#endif

#endif /* OPENSSL_OPENSSLV_H */
"""


def generate_dso_conf_header() -> str:
    return """/* generated by third_party/generate_openssl_headers.py */
#ifndef OSSL_CRYPTO_DSO_CONF_H
#define OSSL_CRYPTO_DSO_CONF_H
#pragma once

#define DSO_WIN32 1
#define DSO_EXTENSION ".dll"

#endif
"""


def generate_fipsindicator_header() -> str:
    return """/* generated by third_party/generate_openssl_headers.py */
#ifndef OSSL_FIPS_FIPSINDICATOR_H
#define OSSL_FIPS_FIPSINDICATOR_H
#pragma once

#define OSSL_FIPS_IND_DECLARE
#define OSSL_FIPS_IND_INIT(ctx)
#define OSSL_FIPS_IND_SET_APPROVED(ctx)
#define OSSL_FIPS_IND_ON_UNAPPROVED(ctx, id, libctx, algname, opname, configopt_fn)
#define OSSL_FIPS_IND_SETTABLE_CTX_PARAM(name)
#define OSSL_FIPS_IND_SET_CTX_PARAM(ctx, id, params, name) 1
#define OSSL_FIPS_IND_GETTABLE_CTX_PARAM()
#define OSSL_FIPS_IND_GET_CTX_PARAM(ctx, params) 1
#define OSSL_FIPS_IND_SET_CTX_FROM_PARAM(ctx, id, p) 1
#define OSSL_FIPS_IND_GET_CTX_FROM_PARAM(ctx, p) 1

#define OSSL_FIPS_IND_COPY(dst, src)

#endif /* OSSL_FIPS_FIPSINDICATOR_H */
"""


def render_param_decoder_block(block: str) -> str:
    block = block.strip()
    if block.startswith("use OpenSSL::paramnames"):
        return ""

    match = PARAM_DECODER_RE.search(block)
    if match is None:
        return block

    decoder_name = match.group("name")
    with_count = match.group("with_count") is not None
    param_entries = [
        (
            param_match.group("key"),
            param_match.group("field"),
            param_match.group("type"),
            param_match.group("mode"),
        )
        for param_match in PARAM_ENTRY_RE.finditer(match.group("body"))
    ]

    field_order: list[str] = []
    field_to_entries: dict[str, list[tuple[str, str, str | None]]] = {}
    for entry in param_entries:
        field = entry[1]
        if field not in field_order:
            field_order.append(field)
        field_to_entries.setdefault(field, []).append(entry)

    def make_param_ctor(key: str, param_type: str) -> str:
        if param_type == "utf8_string":
            return f"OSSL_PARAM_utf8_string({key}, NULL, 0)"
        if param_type == "utf8_ptr":
            return f"OSSL_PARAM_utf8_ptr({key}, NULL, 0)"
        if param_type == "octet_string":
            return f"OSSL_PARAM_octet_string({key}, NULL, 0)"
        if param_type == "octet_ptr":
            return f"OSSL_PARAM_octet_ptr({key}, NULL, 0)"
        if param_type == "int":
            return f"OSSL_PARAM_int({key}, NULL)"
        if param_type == "uint":
            return f"OSSL_PARAM_uint({key}, NULL)"
        if param_type == "uint32":
            return f"OSSL_PARAM_uint32({key}, NULL)"
        if param_type == "uint64":
            return f"OSSL_PARAM_uint64({key}, NULL)"
        if param_type == "ulong":
            return f"OSSL_PARAM_ulong({key}, NULL)"
        if param_type == "int32":
            return f"OSSL_PARAM_int32({key}, NULL)"
        if param_type == "int64":
            return f"OSSL_PARAM_int64({key}, NULL)"
        if param_type == "time_t":
            return f"OSSL_PARAM_time_t({key}, NULL)"
        if param_type == "BN":
            return f"OSSL_PARAM_BN({key}, NULL, 0)"
        if param_type == "size_t":
            return f"OSSL_PARAM_size_t({key}, NULL)"
        raise ValueError(f"Unsupported parameter type: {param_type}")

    lines: list[str] = ["#include <string.h>", ""]
    lines.append(f"static const OSSL_PARAM {decoder_name}_list[] = {{")
    for key, _, param_type, _ in param_entries:
        lines.append(f"    {make_param_ctor(key, param_type)},")
    lines.append("    OSSL_PARAM_END")
    lines.append("};")
    lines.append("")
    lines.append(f"struct {decoder_name}_st {{")
    for field in field_order:
        lines.append(f"    OSSL_PARAM *{field};")
    lines.append("};")
    lines.append("")
    signature = f"static int {decoder_name}_decoder(const OSSL_PARAM *p, struct {decoder_name}_st *r"
    if with_count:
        signature += ", int *count"
    signature += ")"
    lines.append(signature)
    lines.append("{")
    lines.append("    if (r == NULL)")
    lines.append("        return 0;")
    if with_count:
        lines.append("    if (count != NULL)")
        lines.append("        *count = 0;")
    lines.append("    memset(r, 0, sizeof(*r));")
    lines.append("    for (; p != NULL && p->key != NULL; p++) {")
    for index, field in enumerate(field_order):
        prefix = "if" if index == 0 else "else if"
        field_entries = field_to_entries[field]
        comparisons = " || ".join(
            f"strcmp(p->key, {key}) == 0" for key, _, _, _ in field_entries
        )
        lines.append(f"        {prefix} ({comparisons}) {{")
        lines.append(f"            if (r->{field} == NULL) {{")
        lines.append(f"                r->{field} = (OSSL_PARAM *)p;")
        if with_count:
            lines.append("                if (count != NULL)")
            lines.append("                    (*count)++;")
        lines.append("            }")
        lines.append("        }")
    lines.append("    }")
    lines.append("    return 1;")
    lines.append("}")
    return "\n".join(lines)


def render_param_decoder_template(text: str) -> str:
    def replace_block(match: re.Match[str]) -> str:
        block = match.group(1)
        if PARAM_DECODER_RE.search(block):
            return render_param_decoder_block(block)
        return render_expr(block)

    text = re.sub(r"\{-(.*?)-\}", replace_block, text, flags=re.S)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def generate_core_names_header() -> str:
    template_path = ROOT / "include" / "openssl" / "core_names.h.in"
    text = render_template(template_path.read_text(encoding="utf-8"))

    macros: list[str] = []
    for line in PARAMNAMES.read_text(encoding="utf-8").splitlines():
        match = re.match(r"\s*'([^']+)'\s*=>\s*(.+?),(?:\s*#.*)?\s*$", line)
        if not match:
            continue
        macro_name, value = match.groups()
        value = value.strip()
        if value.startswith("'") and value.endswith("'"):
            rendered = value[1:-1]
            macros.append(f'#define {macro_name} "{rendered}"')
        elif value.startswith('"') and value.endswith('"'):
            rendered = value[1:-1]
            macros.append(f'#define {macro_name} "{rendered}"')
        elif value.startswith("*"):
            macros.append(f"#define {macro_name} {value[1:]}")
        else:
            macros.append(f"#define {macro_name} {value}")

    generated_block = (
        "/* Parameter name definitions - generated by util/perl/OpenSSL/paramnames.pm */\n"
        "/* clang-format off */\n" + "\n".join(macros) + "\n/* clang-format on */"
    )

    return re.sub(
        r"/\* Parameter name definitions - generated by util/perl/OpenSSL/paramnames\.pm \*/\n"
        r"/\* clang-format off \*/\n"
        r"(?:\s*\n)*"
        r"/\* clang-format on \*/",
        generated_block,
        text,
        count=1,
    )


def parse_oid_reference(token: str) -> str | int:
    token = token.replace(" ", "")
    if token.isdigit():
        return int(token)

    match = re.fullmatch(r"([A-Za-z][-_A-Za-z0-9]*[A-Za-z0-9]?)(?:\((\d+)\))?", token)
    if match is None:
        raise ValueError(f"Unsupported OID token: {token}")

    name, value = match.groups()
    if value is not None:
        return int(value)
    return name


def parse_asn1_oid_files(
    relative_paths: list[str],
) -> tuple[list[tuple[str, list[int]]], dict[str, list[str | int]]]:
    definitions: dict[str, list[str | int]] = {}
    ordered_names: list[str] = []
    referenced_names: set[str] = set()

    for relative_path in relative_paths:
        text = (ROOT / relative_path).read_text(encoding="utf-8")
        text = re.sub(r"--.*?(?:\r?\n|$)", "", text)
        for match in OID_DEF_RE.finditer(text):
            name = match.group("name")
            value = match.group("value")
            components = [
                parse_oid_reference(token) for token in OID_TOKEN_RE.findall(value)
            ]
            definitions[name] = components
            ordered_names.append(name)
            referenced_names.update(
                part for part in components if isinstance(part, str)
            )

    leaves = [name for name in ordered_names if name not in referenced_names]
    resolved: dict[str, list[int]] = {}

    def resolve(name: str) -> list[int]:
        if name in resolved:
            return resolved[name]
        try:
            components = definitions[name]
        except KeyError as exc:
            raise KeyError(f"Unknown OID reference: {name}") from exc

        expanded: list[int] = []
        for component in components:
            if isinstance(component, int):
                expanded.append(component)
            else:
                expanded.extend(resolve(component))
        resolved[name] = expanded
        return expanded

    return [(name, resolve(name)) for name in leaves], definitions


def encode_oid_arcs(arcs: list[int]) -> list[int]:
    if len(arcs) < 2:
        raise ValueError("An OID must have at least two arcs")

    first, second, *rest = arcs
    encoded = []

    def encode_subidentifier(value: int) -> list[int]:
        if value < 0:
            raise ValueError("OID arcs must be non-negative")
        octets = [value & 0x7F]
        value >>= 7
        while value:
            octets.append(0x80 | (value & 0x7F))
            value >>= 7
        return list(reversed(octets))

    encoded.extend(encode_subidentifier(40 * first + second))

    for arc in rest:
        encoded.extend(encode_subidentifier(arc))

    return encoded


def generate_provider_header(template_path: pathlib.Path) -> str:
    relative_template = template_path.relative_to(ROOT).as_posix()
    try:
        source_files = PROVIDER_HEADER_SPECS[relative_template]
    except KeyError as exc:
        raise KeyError(
            f"No provider ASN.1 spec configured for {relative_template}"
        ) from exc

    oid_entries, _ = parse_asn1_oid_files(source_files)

    blocks: list[str] = []
    for name, arcs in oid_entries:
        c_name = name.replace("-", "_")
        encoded = encode_oid_arcs(arcs)
        byte_list = ", ".join(f"0x{byte:02X}" for byte in encoded)
        blocks.append(
            f"#define DER_OID_V_{c_name} DER_P_OBJECT, {len(encoded)}, {byte_list}\n"
            f"#define DER_OID_SZ_{c_name} {len(encoded) + 2}\n"
            f"extern const unsigned char ossl_der_oid_{c_name}[DER_OID_SZ_{c_name}];"
        )

    rendered = template_path.read_text(encoding="utf-8")
    generated_block = "\n".join(blocks)
    return re.sub(
        r"/\* clang-format off \*/\n\{-[\s\S]*?-\}\n/\* clang-format on \*/",
        f"/* clang-format off */\n{generated_block}\n/* clang-format on */",
        rendered,
        count=1,
    )


def main() -> int:
    output_root = GEN_ROOT
    output_root.mkdir(parents=True, exist_ok=True)

    template_headers = sorted((ROOT / "include" / "openssl").glob("*.h.in"))
    template_headers += [ROOT / "include" / "crypto" / "dso_conf.h.in"]
    template_headers += [
        ROOT / relative_path for relative_path in PROVIDER_HEADER_SPECS
    ]
    template_headers += sorted(ROOT.rglob("*.inc.in"))

    for template_path in template_headers:
        if template_path.is_relative_to(ROOT / "include"):
            relative = template_path.relative_to(ROOT / "include")
        elif template_path.is_relative_to(
            ROOT / "providers" / "common" / "include" / "prov"
        ):
            relative = pathlib.Path("prov") / template_path.name
        else:
            relative = template_path.relative_to(ROOT)
        output_path = output_root / relative.with_suffix("")
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if template_path.name == "configuration.h.in":
            rendered = generate_configuration_header()
        elif template_path.name == "opensslv.h.in":
            rendered = generate_opensslv_header()
        elif template_path.name == "dso_conf.h.in":
            rendered = generate_dso_conf_header()
        elif template_path.name == "core_names.h.in":
            rendered = generate_core_names_header()
        elif template_path.relative_to(ROOT).as_posix() in PROVIDER_HEADER_SPECS:
            rendered = generate_provider_header(template_path)
        else:
            rendered = render_template(template_path.read_text(encoding="utf-8"))

        output_path.write_text(rendered, encoding="utf-8")

    buildinf_path = ROOT / "crypto" / "buildinf.h"
    buildinf_path.write_text(generate_buildinf_header(), encoding="utf-8")

    fipsindicator_path = GEN_ROOT / "fips" / "fipsindicator.h"
    fipsindicator_path.parent.mkdir(parents=True, exist_ok=True)
    fipsindicator_path.write_text(generate_fipsindicator_header(), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
