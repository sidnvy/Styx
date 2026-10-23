# Styx

Styx connects authorized native Linux, macOS and Windows devices to model-facing MCP tools through a Gateway, outbound Host connectors and one shared management Core. Exec, Browser and Computer Use are independent capabilities. Styx does not plan tasks or replay operations with unknown outcomes.

**Developer Preview; Stable release is NO-GO.** The only product source is [`src/`](src/README.md). The previous root implementation was retired in the repository migration; it remains available in Git history at `6fd902e`. There is no parallel legacy runtime or root plugin entrypoint.

- [Installation and first use](INSTALL.md)
- [Product boundaries](src/docs/product-boundaries.md)
- [Release convergence and remaining gates](src/docs/release-convergence.md)
- [Validation](VALIDATION.md)

Use Node.js 22 and the independent lockfiles under `src/` and its three providers. Root npm commands delegate to this source; they do not load another implementation.

```sh
npm --prefix src ci --ignore-scripts --no-audit --no-fund
npm run quality -- /absolute/fresh/evidence-directory
```

Source migration does not rename deployed state, pairing identities, publisher pins, protocol identifiers or signed bundle members. Existing native packages retain their verified internal layout. Historical candidates and test receipts remain bound to their original SHA.
