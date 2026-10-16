# Synthetic archive fixture

`two-cabinets.msi` is an inert 4,608-byte MSI authored by OfficeIMO's test fixture
`OfficeIMO.Archives.Tests/ArchiveFixtures.Msi(twoCabinets: true)`. It contains two
embedded stored cabinets with the text `hello` and `world`. The test reads its
inventory and payloads; it never installs the package or extracts files to disk.

The fixture was generated from OfficeIMO source
`fb1b7fd1f2adcfbfb9ecaf354f4781733f1627c5` using an isolated test-only producer
against its candidate Core and Archives packages. The producer is outside the
shipped dependency graph.

SHA-256: `410642462bbf39aa646fae05d104be3d4890d62840205e48c8dc4ba122b766f7`.
