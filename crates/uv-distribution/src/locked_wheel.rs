use std::io::{self, BufReader, Seek};
use std::path::PathBuf;

use futures::TryStreamExt;
use tokio::io::{AsyncRead, AsyncWriteExt};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use uv_cache::{Cache, CacheBucket, CacheEntry, WheelCache};
use uv_cache_info::Timestamp;
use uv_client::{CacheControl, CachedClientError, Connectivity, RegistryClient, RetryState};
use uv_distribution_types::{ArchiveHashPolicy, BuiltDist, Hashed, Name, VariantsJsonContent};
use uv_extract::hash::{HashReader, Hasher};
use uv_preview::PreviewFeature;
use uv_pypi_types::HashDigest;
use uv_redacted::SafeUrl;

use crate::archive::Archive;
use crate::distribution_database::{lock_wheel, persist_extracted_wheel, validate_hashes};
use crate::extracted_wheel::WheelExtractor;
use crate::hash::http_hash_algorithms;
use crate::{Error, HttpArchivePointer, PathArchivePointer};

enum WheelLocation {
    Path(PathBuf),
    Url(SafeUrl),
}

/// Read the variant metadata from a locked wheel after authenticating it against the lockfile.
///
/// Uses the same wheel cache as installation. A downloaded wheel is hashed in full before any ZIP
/// entry is parsed. This function does not query variant providers.
pub async fn read_locked_wheel_variant(
    client: &RegistryClient,
    cache: &Cache,
    dist: &BuiltDist,
    hashes: &[HashDigest],
) -> Result<Option<VariantsJsonContent>, Error> {
    let filename = dist.wheel_filename();
    let Some(label) = filename.variant() else {
        return Ok(None);
    };
    if hashes.is_empty() {
        return Err(Error::MissingHashes {
            distribution: dist.to_string(),
        });
    }
    let policy = ArchiveHashPolicy::All(hashes);
    let (wheel_cache, location) = match dist {
        BuiltDist::Registry(wheels) => {
            let wheel = wheels.best_wheel();
            let url = wheel.file.url.to_url()?;
            let location = if url.scheme() == "file" {
                WheelLocation::Path(
                    url.to_file_path()
                        .map_err(|()| Error::NonFileUrl(url.clone()))?,
                )
            } else {
                WheelLocation::Url(url)
            };
            (WheelCache::Index(&wheel.index), location)
        }
        BuiltDist::DirectUrl(wheel) => (
            WheelCache::Url(&wheel.url),
            WheelLocation::Url(wheel.url.raw().clone()),
        ),
        BuiltDist::Path(wheel) => (
            WheelCache::Url(&wheel.url),
            WheelLocation::Path(wheel.install_path.to_path_buf()),
        ),
        BuiltDist::GitPath(_) => return Err(Error::HashesNotSupportedGit(dist.to_string())),
    };
    let wheel_entry = cache.entry(
        CacheBucket::Wheels,
        wheel_cache.wheel_dir(dist.name().as_ref()),
        filename.cache_key(),
    );
    let _lock = lock_wheel(&wheel_entry, filename).await?;

    let archive = if let Some(archive) = cached_fragment_wheel(client, cache, dist, policy)? {
        archive
    } else {
        match location {
            WheelLocation::Path(path) => {
                let modified = Timestamp::from_path(&path).map_err(Error::CacheRead)?;
                let pointer_entry = wheel_entry.with_file(format!("{}.rev", filename.cache_key()));
                if let Some(archive) = PathArchivePointer::read_from(&pointer_entry)?
                    .filter(|pointer| pointer.is_up_to_date(modified))
                    .map(PathArchivePointer::into_archive)
                    .filter(|archive| archive.has_digests(policy) && archive.exists(cache))
                {
                    archive
                } else {
                    let file = fs_err::tokio::File::open(&path)
                        .await
                        .map_err(Error::CacheRead)?;
                    let archive =
                        cache_authenticated_wheel(file, cache, &wheel_entry, dist, policy).await?;
                    PathArchivePointer::new(modified, archive.clone())
                        .write_to(&pointer_entry)
                        .await?;
                    archive
                }
            }
            WheelLocation::Url(url) => {
                let http_entry = wheel_entry.with_file(format!("{}.http", filename.cache_key()));
                let control = match client.connectivity() {
                    Connectivity::Online => CacheControl::from(
                        cache
                            .freshness(&http_entry, Some(&filename.name), None)
                            .map_err(Error::CacheRead)?,
                    ),
                    Connectivity::Offline => CacheControl::AllowStale,
                };
                let request = || {
                    client
                        .uncached_client(&url)
                        .get(url.clone())
                        .header("accept-encoding", "identity")
                        .build()
                };
                let download = |response: reqwest::Response, _: &mut RetryState| {
                    let reader = response
                        .bytes_stream()
                        .map_err(io::Error::other)
                        .into_async_read()
                        .compat();
                    cache_authenticated_wheel(reader, cache, &wheel_entry, dist, policy)
                };
                let archive: Archive = client
                    .cached_client()
                    .get_serde_with_retry(request()?, &http_entry, control.clone(), download)
                    .await
                    .map_err(cache_error)?;
                if archive.has_digests(policy) && archive.exists(cache) {
                    archive
                } else {
                    client
                        .cached_client()
                        .skip_cache_with_retry(request()?, &http_entry, control, download)
                        .await
                        .map_err(cache_error)?
                }
            }
        }
    };
    if !archive.satisfies(policy) {
        return Err(Error::hash_mismatch(
            dist.to_string(),
            hashes,
            archive.hashes(),
        ));
    }
    let path = cache.archive(&archive.id);
    let stem = uv_metadata::find_flat_dist_info(filename, &path)
        .map_err(|err| Error::LockedWheelVariant(dist.to_string(), Box::new(err)))?;
    let metadata = uv_metadata::read_wheel_variant(
        &path.join(format!("{stem}.dist-info/variant.json")),
        label,
    )
    .map_err(|err| Error::LockedWheelVariant(dist.to_string(), Box::new(err)))?;
    Ok(Some(metadata))
}

/// A lockfile may omit the original URL's hash fragment, which is part of the wheel cache key.
fn cached_fragment_wheel(
    client: &RegistryClient,
    cache: &Cache,
    dist: &BuiltDist,
    policy: ArchiveHashPolicy<'_>,
) -> Result<Option<Archive>, Error> {
    let BuiltDist::DirectUrl(wheel) = dist else {
        return Ok(None);
    };
    if client.connectivity() != Connectivity::Offline || wheel.url.fragment().is_some() {
        return Ok(None);
    }
    for hash in policy.digests() {
        let mut url = wheel.url.raw().clone();
        url.set_fragment(Some(&format!("{}={}", hash.algorithm(), hash.digest())));
        let entry = cache.entry(
            CacheBucket::Wheels,
            WheelCache::Url(&url).wheel_dir(wheel.name().as_ref()),
            format!("{}.http", wheel.filename.cache_key()),
        );
        if let Some(archive) = HttpArchivePointer::read_from(&entry)?
            .map(HttpArchivePointer::into_archive)
            .filter(|archive| archive.filename == wheel.filename)
            .filter(|archive| archive.satisfies(policy) && archive.exists(cache))
        {
            return Ok(Some(archive));
        }
    }
    Ok(None)
}

fn cache_error(err: CachedClientError<Error>) -> Error {
    match err {
        CachedClientError::Callback { err, .. } => err,
        CachedClientError::Client(err) => Error::Client(err),
    }
}

/// Authenticate a stable copy before opening the archive, then publish it to the wheel cache.
async fn cache_authenticated_wheel(
    reader: impl AsyncRead + Unpin,
    cache: &Cache,
    wheel_entry: &CacheEntry,
    dist: &BuiltDist,
    policy: ArchiveHashPolicy<'_>,
) -> Result<Archive, Error> {
    let file = tempfile::tempfile_in(cache.root()).map_err(Error::CacheWrite)?;
    let mut file = tokio::io::BufWriter::new(fs_err::tokio::File::from_std(
        fs_err::File::from_parts(file, cache.root()),
    ));
    let mut hashers = http_hash_algorithms(policy)
        .into_iter()
        .map(Hasher::from)
        .collect::<Vec<_>>();
    let mut reader = HashReader::new(reader, &mut hashers);
    let size = tokio::io::copy(&mut reader, &mut file)
        .await
        .map_err(Error::HashExhaustion)?;
    file.flush().await.map_err(Error::CacheWrite)?;
    let hashes = validate_hashes(dist, policy, hashers)?;
    let mut file = file.into_inner().into_std().await;
    let root = cache.root().to_path_buf();
    let filename = dist.wheel_filename().clone();
    let distribution = dist.to_string();
    let content_addressed = uv_preview::is_enabled(PreviewFeature::ContentAddressedCache)
        && !uv_extract::insecure_no_validate();
    let mut extracted = tokio::task::spawn_blocking(move || {
        file.rewind().map_err(Error::CacheRead)?;
        uv_metadata::read_archive_wheel_variant(&filename, BufReader::new(&mut file))
            .map_err(|err| Error::LockedWheelVariant(distribution, Box::new(err)))?;
        file.rewind().map_err(Error::CacheRead)?;
        WheelExtractor::new(&root, content_addressed)
            .map_err(Error::CacheWrite)?
            .extract_seekable(file)
            .map_err(|err| Error::Extract(filename.to_string(), err))
    })
    .await??;
    extracted.validate_and_heal_record(dist)?;
    let id = persist_extracted_wheel(cache, extracted, wheel_entry.path()).await?;
    Ok(Archive::new(
        id,
        hashes,
        dist.wheel_filename().clone(),
        Some(size),
    ))
}
