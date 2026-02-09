use std::{ops::Bound, sync::Arc};

use axum::{extract::State, Json};
use semver::Version;

use super::JsonResult;
use crate::{middleware::server_auth::AuthorizedServer, AuthServer};

// [GET] /api/get_version_ranges
#[axum::debug_handler]
pub async fn get_version_ranges(
    State(_state): State<Arc<AuthServer>>, AuthorizedServer(_token, _server): AuthorizedServer,
    Json(versions): Json<Vec<String>>,
) -> JsonResult<Vec<String>, String> {
    let versions: Vec<_> = versions
        .iter()
        .filter_map(|it| Version::parse(it).ok())
        .collect();

    let ranges = simplify_ranges(versions)
        .iter()
        .map(|it| format!("{}-{}", it.0, it.1))
        .collect();

    Ok(Json(ranges))
}

fn simplify_ranges(mut items: Vec<Version>) -> Vec<(Version, Version)> {
    if items.is_empty() {
        return Vec::new();
    }

    items.sort();

    let mut ranges = Vec::new();
    let mut start = items[0].clone();
    let mut prev = items[0].clone();

    for curr in items.iter().skip(1).cloned() {
        if !(curr.major == prev.major && curr.minor == prev.minor && curr.patch == prev.patch + 1) {
            ranges.push((start.clone(), prev.clone()));
            start = curr.clone();
        }

        prev = curr;
    }

    ranges.push((start, prev));

    ranges
}
