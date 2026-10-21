#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
mod aarch64;
mod nvidia;
#[cfg(target_arch = "x86_64")]
mod x86_64;

use tracing::debug;
use uv_distribution_filename::VariantLabel;
use uv_distribution_types::{
    InstalledDist, SelectedVariant, SupportedVariantFeature, SupportedVariantProperties,
    VariantNamespace, VariantProviderRequest, VariantsJsonContent,
};
use uv_pep440::Version;
use uv_pep508::{Requirement, VersionOrUrl};
use uv_preview::PreviewFeature;
use uv_types::BuildContext;

use crate::Error;
#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
use crate::variant::aarch64::Aarch64VariantProvider;
use crate::variant::nvidia::NvidiaVariantProvider;
#[cfg(target_arch = "x86_64")]
use crate::variant::x86_64::X86_64VariantProvider;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
static AARCH64_PROVIDER: Aarch64VariantProvider = Aarch64VariantProvider;
static NVIDIA_PROVIDER: NvidiaVariantProvider = NvidiaVariantProvider::new();
#[cfg(target_arch = "x86_64")]
static X86_64_PROVIDER: X86_64VariantProvider = X86_64VariantProvider;
static VENDORED_PROVIDERS: &[&dyn VendoredVariantProvider] = &[
    #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
    &AARCH64_PROVIDER,
    &NVIDIA_PROVIDER,
    #[cfg(target_arch = "x86_64")]
    &X86_64_PROVIDER,
];

/// Whether an installed wheel's variant is compatible with the current system.
#[derive(Debug)]
pub enum InstalledWheelVariant {
    NonVariant,
    Compatible(VariantLabel),
    Incompatible,
}

impl InstalledWheelVariant {
    pub fn check(installed: &InstalledDist) -> Self {
        Self::check_with_target(installed, None)
    }

    /// Check the installed properties against an explicit target or the current system.
    pub fn check_with_target(
        installed: &InstalledDist,
        target: Option<&SupportedVariantProperties>,
    ) -> Self {
        Self::check_using(installed, |metadata, recorded| match target {
            Some(target) => metadata.select_variant(&recorded.label, target),
            None => metadata.select_variant(
                &recorded.label,
                &recheckable_installed_properties(metadata, recorded),
            ),
        })
    }

    /// Check an installed wheel against properties already selected during resolution.
    pub fn check_with_selected(installed: &InstalledDist, selected: &SelectedVariant) -> Self {
        Self::check_using(installed, |_, _| Some(selected.clone()))
    }

    fn check_using(
        installed: &InstalledDist,
        select: impl FnOnce(&VariantsJsonContent, &SelectedVariant) -> Option<SelectedVariant>,
    ) -> Self {
        let metadata = match installed.read_variant() {
            Ok(None) => return Self::NonVariant,
            Ok(Some(metadata)) => metadata,
            Err(err) => {
                debug!("Failed to read variant metadata for {installed}: {err}");
                return Self::Incompatible;
            }
        };
        if uv_preview::is_enabled(PreviewFeature::WheelVariants)
            && let Ok(recorded) = installed.read_variant_context_for_metadata(&metadata)
            && let Some(selected) = select(&metadata, &recorded)
            && recorded == selected
        {
            return Self::Compatible(selected.label);
        }
        Self::Incompatible
    }

    /// Whether the installed distribution is compatible with the current system.
    pub fn is_compatible(&self) -> bool {
        match self {
            // TODO(konsti): Consider higher-ranked variants even when this one is compatible.
            Self::NonVariant | Self::Compatible(_) => true,
            Self::Incompatible => false,
        }
    }

    /// Whether this wheel matches the variant selected for installation.
    pub fn matches(&self, expected: Option<&VariantLabel>) -> bool {
        match self {
            Self::NonVariant => expected.is_none(),
            Self::Compatible(label) => expected == Some(label),
            Self::Incompatible => false,
        }
    }
}

/// Check properties uv can detect directly. A required external provider leaves a namespace
/// missing, forcing policy-aware resolution before the installed wheel can be reused.
fn recheckable_installed_properties(
    metadata: &VariantsJsonContent,
    recorded: &SelectedVariant,
) -> SupportedVariantProperties {
    let mut supported = SupportedVariantProperties::default();
    for (namespace, provider) in metadata.providers() {
        if !recorded.properties.contains_key(namespace) {
            continue;
        }
        if let Some(features) = provider.static_properties() {
            supported.insert(namespace.clone(), &features);
            continue;
        }
        let Some(request) = provider.request() else {
            continue;
        };
        if let Some(provider) = find_vendored_provider(namespace, request)
            && let Some(features) = provider.properties()
        {
            supported.insert(namespace.clone(), features);
        }
    }
    supported
}

/// A vendored wheel variant provider.
trait VendoredVariantProvider: Sync {
    fn namespace(&self) -> &str;
    /// The API endpoint, or `None` to use the default derived from the package name.
    fn plugin_api(&self) -> Option<&str>;
    /// The normalized name of the provider package.
    fn package_name(&self) -> &str;
    fn package_version(&self) -> Version;
    fn properties(&self) -> Option<&[SupportedVariantFeature]>;
}

/// Collect the variant properties supported by enabled static and vendored providers.
pub fn supported_variant_properties(metadata: &VariantsJsonContent) -> SupportedVariantProperties {
    let detected = metadata
        .provider_requests()
        .filter_map(|(namespace, request)| {
            let Some(provider) = find_vendored_provider(namespace, request) else {
                // Synchronous compatibility checks can only use trusted implementations.
                let provider_name = match request {
                    VariantProviderRequest::Plugin { plugin_api, .. } => plugin_api,
                    VariantProviderRequest::Builtin(name) => Some(name),
                }
                .unwrap_or("<default>");
                debug!(
                    "Skipping unsupported wheel variant provider `{provider_name}` for namespace \
                     `{namespace}`"
                );
                return None;
            };
            Some((namespace, provider.properties()?))
        });
    metadata.supported_properties(detected)
}

/// Collect compatible properties according to the PEP 850 provider selection algorithm.
pub(crate) async fn query_supported_variant_properties(
    metadata: &VariantsJsonContent,
    context: &impl BuildContext,
    require_hashes: bool,
) -> Result<SupportedVariantProperties, Error> {
    let policy = context.variant_policy();
    if let Some(target) = policy.and_then(|policy| policy.target()) {
        return Ok(target.clone());
    }

    let mut supported = SupportedVariantProperties::default();
    for (namespace, provider) in metadata.providers() {
        let enabled = policy.is_some_and(|policy| policy.enables(namespace));
        if provider.optional() && !enabled {
            continue;
        }
        if let Some(features) = provider.static_properties() {
            supported.insert(namespace.clone(), &features);
            continue;
        }
        let Some(request) = provider.request() else {
            continue;
        };
        if let Some(provider) = find_vendored_provider(namespace, request) {
            if let Some(features) = provider.properties() {
                supported.insert(namespace.clone(), features);
            }
            continue;
        }
        let VariantProviderRequest::Plugin {
            requires,
            plugin_api,
        } = request
        else {
            continue;
        };
        let Some(opt_in) = policy.and_then(|policy| policy.opt_in(namespace)) else {
            debug!("Skipping wheel variant provider for namespace `{namespace}` without opt-in");
            continue;
        };
        if !opt_in.permits_plugin() {
            continue;
        }
        let Some(features) = context
            .query_variant_provider(requires, plugin_api, opt_in, require_hashes)
            .await
            .map_err(|source| Error::VariantProvider {
                namespace: namespace.clone(),
                source,
            })?
        else {
            debug!(
                "Skipping wheel variant provider for namespace `{namespace}` because its identity was not authorized"
            );
            continue;
        };
        metadata
            .validate_plugin_features(namespace, &features)
            .map_err(|source| Error::VariantProvider {
                namespace: namespace.clone(),
                source: source.into(),
            })?;
        let features = features
            .into_iter()
            .map(|feature| SupportedVariantFeature {
                name: feature.name,
                values: feature.values,
            })
            .collect::<Vec<_>>();
        supported.insert(namespace.clone(), &features);
    }
    Ok(supported)
}

/// Find a vendored provider that satisfies a plugin request without installing other packages.
fn find_vendored_provider(
    namespace: &VariantNamespace,
    request: VariantProviderRequest<'_>,
) -> Option<&'static dyn VendoredVariantProvider> {
    let (requires, plugin_api) = match request {
        VariantProviderRequest::Plugin {
            requires,
            plugin_api,
        } => (requires, plugin_api),
        VariantProviderRequest::Builtin(_) => return None,
    };
    let [requirement] = requires else {
        return None;
    };
    // Reject unsupported markers before the requirement parser recurses into them.
    if requirement.contains(';') {
        return None;
    }
    let requirement = requirement.parse::<Requirement>().ok()?;
    if !requirement.extras.is_empty() {
        return None;
    }
    let specifiers = match requirement.version_or_url {
        Some(VersionOrUrl::VersionSpecifier(specifiers)) => Some(specifiers),
        Some(VersionOrUrl::Url(_)) => return None,
        None => None,
    };
    let default_plugin_api = requirement.name.as_dist_info_name();
    let plugin_api = plugin_api.unwrap_or(default_plugin_api.as_ref());
    VENDORED_PROVIDERS
        .iter()
        .copied()
        .find(|provider| {
            provider.package_name() == requirement.name.as_str()
                && provider.plugin_api().unwrap_or(default_plugin_api.as_ref()) == plugin_api
                && specifiers
                    .as_ref()
                    .is_none_or(|specifiers| specifiers.contains(&provider.package_version()))
        })
        .inspect(|provider| {
            debug!(
                "Using trusted `{}` provider for variant namespace `{namespace}`",
                provider.namespace()
            );
        })
}
