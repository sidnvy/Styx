use super::AppError;
use crate::store::{ExecutionLeaseGuard, PrivateRoot};
use std::{
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
};

/// Retained original App container and its one instance lease. The child root's
/// configuration writer remains separate and is acquired ONLY by existing C07
/// operations. Arc retains this owner; wire DATA cannot construct/replace it.
/// This protects cooperative same-user lifecycle ownership, not against a
/// malicious process already able to execute as the same OS account.
pub(super) struct AppContainer {
    pub(super) parent_path: PathBuf,
    pub(super) parent: PrivateRoot,
    pub(super) instance: ExecutionLeaseGuard,
}

pub(crate) struct HostScope {
    pub(super) container: Arc<AppContainer>,
    pub(super) state_dir: PathBuf,
    pub(super) root: OnceLock<PrivateRoot>,
}

impl HostScope {
    #[cfg(test)]
    pub(crate) fn open_for_test(state_dir: &Path) -> Result<Self, AppError> {
        Self::open(state_dir)
    }
    pub(super) fn open(state_dir: &Path) -> Result<Self, AppError> {
        if !state_dir.is_absolute()
            || state_dir.components().any(|p| {
                !matches!(
                    p,
                    Component::Normal(_) | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(AppError("app_scope_invalid"));
        }
        let parent_path = state_dir
            .parent()
            .ok_or(AppError("app_scope_invalid"))?
            .to_owned();
        let parent = PrivateRoot::open(&parent_path).map_err(|_| AppError("app_scope_refused"))?;
        // The container is never itself an active native configuration root.
        parent
            .ensure_absent(".styx-native-root-v1.json")
            .map_err(|_| AppError("app_container_is_configuration"))?;
        for name in ["state.json", "deployment.json"] {
            parent
                .ensure_absent(name)
                .map_err(|_| AppError("app_container_is_configuration"))?;
        }
        let instance = parent
            .try_execution_lease()
            .map_err(|_| AppError("app_instance_busy"))?;
        let container = Arc::new(AppContainer {
            parent_path,
            parent,
            instance,
        });
        crate::management::role_retire::check_app_retire_journal(
            &container.parent,
            &container.parent_path,
        )
        .map_err(|_| AppError("app_role_retire_unknown"))?;
        Self::in_container(container, state_dir.to_owned())
    }
    pub(super) fn in_container(
        container: Arc<AppContainer>,
        state_dir: PathBuf,
    ) -> Result<Self, AppError> {
        if state_dir.parent() != Some(container.parent_path.as_path()) {
            return Err(AppError("app_scope_invalid"));
        }
        let name = state_dir.file_name().ok_or(AppError("app_scope_invalid"))?;
        let root = OnceLock::new();
        if container.parent.ensure_absent(Path::new(name)).is_err() {
            let original =
                PrivateRoot::open(&state_dir).map_err(|_| AppError("app_scope_refused"))?;
            root.set(original)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        let result = Self {
            container,
            state_dir,
            root,
        };
        result.validate()?;
        Ok(result)
    }
    /// A fixed sibling under the SAME original App instance lease. Neither the
    /// wire caller nor a second App process can choose or acquire another owner.
    pub(super) fn gateway_sibling(&self) -> Result<Self, AppError> {
        self.validate()?;
        let state_dir = self.container.parent_path.join("gateway");
        if state_dir == self.state_dir {
            return Err(AppError("app_role_scope_conflict"));
        }
        Self::in_container(self.container.clone(), state_dir)
    }
    pub(crate) fn state_dir(&self) -> &Path {
        &self.state_dir
    }
    pub(crate) fn validate(&self) -> Result<(), AppError> {
        self.container
            .instance
            .validate()
            .map_err(|_| AppError("app_instance_changed"))?;
        let parent = PrivateRoot::open(&self.container.parent_path)
            .map_err(|_| AppError("app_scope_changed"))?;
        if parent.identity() != self.container.parent.identity() {
            return Err(AppError("app_scope_changed"));
        }
        for name in [".styx-native-root-v1.json", "state.json", "deployment.json"] {
            parent
                .ensure_absent(name)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        match self.root.get() {
            Some(original) => {
                let current = PrivateRoot::open(&self.state_dir)
                    .map_err(|_| AppError("app_scope_changed"))?;
                if current.identity() != original.identity() {
                    return Err(AppError("app_scope_changed"));
                }
            }
            None => self
                .container
                .parent
                .ensure_absent(Path::new(
                    self.state_dir
                        .file_name()
                        .ok_or(AppError("app_scope_invalid"))?,
                ))
                .map_err(|_| AppError("app_scope_changed"))?,
        }
        Ok(())
    }
    /// A join attempt owns its child handles until transport settlement. The
    /// App binds its long-lived scope only after that operation returns.
    pub(crate) fn scope_for_join(&self) -> Result<Arc<Self>, AppError> {
        self.validate()?;
        if self.root.get().is_some() {
            return Err(AppError("app_join_already_exists"));
        }
        Ok(Arc::new(Self::in_container(
            self.container.clone(),
            self.state_dir.clone(),
        )?))
    }
    pub(crate) fn unsent_join_inputs(&self) -> Vec<PathBuf> {
        [
            "app-join-input-v1.json",
            "app-join-ca-v1.pem",
            "app-join-invitation-v1",
        ]
        .into_iter()
        .map(|name| self.container.parent_path.join(name))
        .collect()
    }
    pub(crate) fn bind(&self) -> Result<(), AppError> {
        if self.root.get().is_none() {
            let root =
                PrivateRoot::open(&self.state_dir).map_err(|_| AppError("app_scope_changed"))?;
            self.root
                .set(root)
                .map_err(|_| AppError("app_scope_changed"))?;
        }
        self.validate()
    }
}
