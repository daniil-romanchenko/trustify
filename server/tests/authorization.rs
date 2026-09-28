//! Ensure every API endpoint has been classified for scoped authorization.
//!
//! When adding an endpoint, decide how it is affected by `TRUSTD_AUTHZ_MODE=scoped`, and add it to
//! [`ENDPOINTS`]. An endpoint returning or modifying SBOM data must enforce the `AccessScope`.

use std::{collections::BTreeSet, fs, io, path::Path};

#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
enum Class {
    /// Enforces the access scope: SBOMs, or data derived from them, are filtered.
    Scoped,
    /// Data which is shared by all users, like advisories. References to SBOMs are filtered.
    Shared,
    /// Tenancy management, with its own (possibly delegated) authorization.
    Tenancy,
    /// Platform operations, only authorized by global permissions.
    Platform,
}

use Class::*;

const ENDPOINTS: &[(&str, Class)] = &[
    ("/api/v2/purl/recommend", Shared),
    ("/api/v2/sbom", Scoped),
    ("/api/v2/vulnerability/analyze", Shared),
    ("/api/v3/advisory", Shared),
    ("/api/v3/advisory-labels", Shared),
    ("/api/v3/advisory/{id}/label", Platform),
    ("/api/v3/advisory/{key}", Shared),
    ("/api/v3/advisory/{key}/download", Shared),
    ("/api/v3/analysis/component", Scoped),
    ("/api/v3/analysis/component/{key}", Scoped),
    ("/api/v3/analysis/latest/component", Scoped),
    ("/api/v3/analysis/latest/component/{key}", Scoped),
    ("/api/v3/analysis/sbom/{sbom}/render.{ext}", Scoped),
    ("/api/v3/analysis/status", Platform),
    ("/api/v3/api-key", Tenancy),
    ("/api/v3/api-key/{key}", Tenancy),
    ("/api/v3/api-key/{key}/rotate", Tenancy),
    ("/api/v3/audit", Tenancy),
    ("/api/v3/dataset", Platform),
    ("/api/v3/exploit", Shared),
    ("/api/v3/exploit-intelligence/analyze", Scoped),
    ("/api/v3/exploit-intelligence/jobs", Scoped),
    ("/api/v3/exploit-intelligence/jobs/{id}", Scoped),
    ("/api/v3/exploit/{id}", Shared),
    ("/api/v3/group/sbom", Scoped),
    ("/api/v3/group/sbom-assignment", Scoped),
    ("/api/v3/group/sbom-assignment/{id}", Scoped),
    ("/api/v3/group/sbom/{group}/binding", Tenancy),
    ("/api/v3/group/sbom/{group}/binding/team/{team}", Tenancy),
    ("/api/v3/group/sbom/{group}/binding/user/{email}", Tenancy),
    ("/api/v3/group/sbom/{id}", Scoped),
    ("/api/v3/importer", Platform),
    ("/api/v3/importer/{name}", Platform),
    ("/api/v3/importer/{name}/enabled", Platform),
    ("/api/v3/importer/{name}/force", Platform),
    ("/api/v3/importer/{name}/report", Platform),
    ("/api/v3/license", Shared),
    ("/api/v3/license/spdx/license", Shared),
    ("/api/v3/license/spdx/license/{id}", Shared),
    ("/api/v3/me", Tenancy),
    ("/api/v3/organization", Shared),
    ("/api/v3/organization/{id}", Shared),
    ("/api/v3/product", Shared),
    ("/api/v3/product/{id}", Shared),
    ("/api/v3/purl", Shared),
    ("/api/v3/purl/base", Shared),
    ("/api/v3/purl/base/{key}", Shared),
    ("/api/v3/purl/recommend", Shared),
    ("/api/v3/purl/recommend/report", Scoped),
    ("/api/v3/purl/{key}", Shared),
    ("/api/v3/sbom", Scoped),
    ("/api/v3/sbom-labels", Scoped),
    ("/api/v3/sbom-permissions", Scoped),
    ("/api/v3/sbom/by-package", Scoped),
    ("/api/v3/sbom/count-by-package", Scoped),
    ("/api/v3/sbom/models", Scoped),
    ("/api/v3/sbom/{id}", Scoped),
    ("/api/v3/sbom/{id}/advisory", Scoped),
    ("/api/v3/sbom/{id}/all-license-ids", Scoped),
    ("/api/v3/sbom/{id}/label", Scoped),
    ("/api/v3/sbom/{id}/license-export", Scoped),
    ("/api/v3/sbom/{id}/models", Scoped),
    ("/api/v3/sbom/{id}/packages", Scoped),
    ("/api/v3/sbom/{id}/related", Scoped),
    ("/api/v3/sbom/{key}/download", Scoped),
    ("/api/v3/team", Tenancy),
    ("/api/v3/team/{key}", Tenancy),
    ("/api/v3/team/{key}/member", Tenancy),
    ("/api/v3/team/{key}/member/{email}", Tenancy),
    ("/api/v3/ui/extract-sbom-purls", Shared),
    ("/api/v3/user", Tenancy),
    ("/api/v3/user/{email}", Tenancy),
    ("/api/v3/user/{email}/access", Tenancy),
    ("/api/v3/user/{email}/change-email", Tenancy),
    ("/api/v3/userPreference/{key}", Platform),
    ("/api/v3/vulnerability", Shared),
    ("/api/v3/vulnerability/analyze", Shared),
    ("/api/v3/vulnerability/{id}", Shared),
    ("/api/v3/weakness", Shared),
    ("/api/v3/weakness/{id}", Shared),
];

/// Extract the paths from the OpenAPI spec, without parsing the whole YAML.
fn api_paths() -> io::Result<BTreeSet<String>> {
    let spec = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../openapi.yaml"))?;

    Ok(spec
        .lines()
        .filter_map(|line| line.strip_prefix("  /api/"))
        .filter_map(|line| line.strip_suffix(':'))
        .map(|path| format!("/api/{path}"))
        .collect())
}

#[test]
fn all_endpoints_classified() -> io::Result<()> {
    let classified: BTreeSet<String> = ENDPOINTS.iter().map(|(path, _)| path.to_string()).collect();
    let actual = api_paths()?;

    let missing: Vec<_> = actual.difference(&classified).collect();
    assert!(
        missing.is_empty(),
        "Endpoints without an authorization class, add them to ENDPOINTS in {}: {missing:#?}",
        file!()
    );

    let stale: Vec<_> = classified.difference(&actual).collect();
    assert!(
        stale.is_empty(),
        "Classified endpoints which no longer exist, remove them from ENDPOINTS in {}: {stale:#?}",
        file!()
    );

    Ok(())
}
