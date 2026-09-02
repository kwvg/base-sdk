# Documentation

This guide is generated using [Zensical](https://pypi.org/project/zensical/) (a fork of
[MkDocs](https://pypi.org/project/mkdocs/)), with additional [pre](#preprocessing)- and
[post](#postprocessing)-processing to make the source material render adequately on the forge provider, GitHub.

## Installing dependencies

> [!NOTE]
> If you haven't set up your development environment, check out the [startup guide](./getting_started.md) first.

The documentation comes bundled with web-ready demos, which are powered by WebAssembly. Preparing them for
distribution relies on [`wasm-pack`](https://github.com/wasm-bindgen/wasm-pack), which is installed as a binary crate.

> [!TIP]
> The [development shell](./devshell.md) already carries `wasm-pack`, so this step can be skipped if you are working
> in one.

```bash
cargo install wasm-pack
```

## Building

> [!WARNING]
> Due to a limitation in Zensical, the target bundle cannot be emitted in the usual `public/` directory.
> This is because a target path must be at or in a child directory relative to [`zensical.toml`](../zensical.toml).
> For more information, see [zensical/backlog#56](https://github.com/zensical/backlog/issues/56).

To generate the target bundle, run the following from the repository root. The target bundle will be located at
`docs/.site`.

```bash
python docs/build_docs.py build
```

### Preview

> [!TIP]
> If a preview appears stale even after rebuilding, you may need to clear `docs/.{cache,site}`.

To preview the site live, run the following from the repository root.

```bash
python docs/build_docs.py preview
```

Live reload is unsupported due to additional processing and compilation artifacts. Using `zensical` directly for
previews or builds may result in a broken site.

## Preprocessing

This documentation has two audiences, GitHub and Zensical. This created an impasse between two competing Markdown
extensions, [GitHub-flavoured Markdown](https://github.github.com/gfm/) (GFM) and
[Python-Markdown](https://pypi.org/project/Markdown/) syntax. Two measures resolve it.

* Naming base pages `README.md` instead of `index.md`, so that GitHub renders a directory's associated base page instead
  of returning empty.
* Processing Markdown files (see [`preprocess.py`](../preprocess.py)) through a Python-Markdown extension before it is
  rendered by Zensical as a webpage.

### Admonitions

The Python ecosystem settled on a syntax for [admonitions](https://zensical.org/docs/authoring/admonitions/) that can
then be extended by Zensical to offer arbitrary icons and accent colors with adequate theming. By contrast, GFM alerts
are relatively rigid but are broadly supported in the Markdown ecosystem (including by WYSIWYG editors like
[Typora](https://typora.io/)).

To bridge this gap, alerts are mapped to the nearest fitting admonition, `[!IMPORTANT]` becomes `info` and `[!CAUTION]`
becomes `danger`.

### Link processing

> [!TIP]
> To cite specific line (ranges), it is advised to link against a commit-pinned version of that file on GitHub (or
> elsewhere reachable on the open web) to ensure that the ranges don't turn stale as the codebase evolves.

On-disk link targets are written relative to the file defining it, as only files under `docs/` are carried into the
target bundle. To allow links outside `docs/` to resolve to a valid path, links pointing to valid on-disk elements
outside `docs/` resolve to the forge instead.

> [!WARNING]
> Zensical treats on-disk `.md` links as documentation and will fail to build if they are located outside `docs/`.
> This does not affect non-Markdown files and directories.

## Postprocessing

> [!WARNING]
> The following is a workaround. Zensical does not offer a setting to hold a file back from the target bundle.
> Support for `not_in_nav` ([zensical/backlog#63](https://github.com/zensical/backlog/issues/63)) as well as
> `exclude_docs` and `draft_docs` ([zensical/backlog#65](https://github.com/zensical/backlog/issues/65)) is pending.

Zensical copies the whole of `docs/` into the target bundle, so sources, manifests, scripts and other non-publishable
materials are included in the target bundle and may end up exposed on the open web. To avoid this,
[`.zenignore`](../.zenignore) lists globs for elements to be excluded from the target bundle. **While `.zenignore` has
similar syntax to `.gitignore`, exclusions (`!`) are not supported and will result in a hard error.**
